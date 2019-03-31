# coding=utf-8
from tools.oc_type_parser import *
import os
import re
import networkx as nx
import copy
from tools.TypeInfer import TypeInfer

RET = 'as return value'
REC = 'as receiver'
ARG = 'as argument'
GEN_PARA = 'as parameter'
GEN_API = 'as generator'


class ETree:

    def __init__(self, etree_file):
        self.eTree = nx.drawing.nx_agraph.read_dot(etree_file)
        self.start_node = self.eTree.graph['start']
        self.ret_nodes = eval(self.eTree.graph['ret'])
        self.traces = []

    def traverse(self):

        if self.start_node:
            Trace.deadend_traces = []
            Trace.alive_traces = []
            init_trace = Trace(self.eTree, start=self.start_node)
            Trace.alive_traces.append(init_trace)

            while Trace.alive_traces:
                round = list(Trace.alive_traces)
                for trace in round:
                    if trace.alive:
                        trace.step()
            self.traces = Trace.deadend_traces

        else:
            print "Cannot find the start node."

        return self.traces

    def query_ret_values(self):
        for node in self.ret_nodes:
            data = self.eTree.nodes[node]
            print data


class Trace:

    alive_traces = []
    deadend_traces = []

    def __init__(self, tree, start=None, pre_existing=None):
        """
        执行树中的一条路径。
        :param tree: 执行树
        :param start:
        :param pre_existing:
        """
        self.tree = tree
        if start:
            self.route = [start, ]
        else:
            self.route = pre_existing
        self.alive = True

        # 该路径中被污染的子路径，可能有多条（有多个匹配的起始节点）
        self.tainted_subtrace = None
        # 该路径中 地址-节点 的映射字典
        self.ea_node = dict()

    def terminate(self):
        self.alive = False
        Trace.alive_traces.remove(self)
        Trace.deadend_traces.append(self)

    def step(self):
        out_edges = self.tree.out_edges(self.route[-1])
        if len(out_edges) == 0:
            # print "Trace terminated at {}.".format(self.route[-1])
            self.terminate()
        elif len(out_edges) == 1:
            self.route.append(list(out_edges)[0][-1])
        elif len(out_edges) > 1:
            for edge in list(out_edges)[1:]:
                forked_trace = Trace(self.tree, pre_existing=copy.deepcopy(self.route))
                forked_trace.route.append(edge[-1])
                Trace.alive_traces.append(forked_trace)
            self.route.append(list(out_edges)[0][-1])
        else:
            print '??? WHY ???'

    def taint_analyze(self, rec=None, sel=None, as_parameter=None, rule=None):
        tainted_subtrace = []
        start_node = self.tree.graph['start']
        ret_nodes = eval(self.tree.graph['ret'])
        tainted_data = []

        # 在level为0时，根据规则进行分析
        if rule:
            rec = rule['Receiver']
            sel = rule['Selector']
            as_parameter = rule['Index']

        # 被标记数据作为参数传入，该值为参数的index. None表示该数据不作为参数，而是以API返回值方式产生。
        if as_parameter is not None:
            if 'args' in self.tree.nodes[start_node]:
                node_data = self.tree.nodes[start_node]
                tainted_data.append(eval(node_data['args'])[as_parameter])
                tainted_subtrace.append(
                    {
                        'type': GEN_PARA,
                        'rec': node_data['rec'],
                        'sel': node_data['sel'],
                        'data': eval(node_data['args'])[as_parameter],
                        'ea': node_data['addr'],
                        'ctx': node_data['context'],
                        'ctx_name': node_data['context_name'],
                        'node': start_node
                    }
                )

        for node in self.route:
            node_data = self.tree.nodes[node]
            self.ea_node[int(node_data['addr'])] = node_data

            # 根据rec和sel判断该节点是否为隐私数据的产生者
            if 'sel' in node_data and sel == node_data['sel']:
                if 'rec' in node_data and TypeInfer.type_match(rec, node_data, sel, self):
                    if 'ret' in node_data and node_data['ret']:
                        tainted_subtrace.append(
                            {
                                'type': GEN_API,
                                'rec': node_data['rec'],
                                'sel': node_data['sel'],
                                'data': node_data['ret'],
                                'ea': node_data['addr'],
                                'ctx': node_data['context'],
                                'ctx_name': node_data['context_name'],
                                'node': node
                            }
                        )
                        tainted_data.append(node_data['ret'])

            if 'rec' in node_data and self.tainted(node_data['rec'], tainted_data):
                tainted_subtrace.append(
                    {
                        'type': REC,
                        'rec': node_data['rec'],
                        'sel': node_data['sel'],
                        'data': self.tainted(node_data['rec'], tainted_data),
                        'ea': node_data['addr'],
                        'ctx': node_data['context'],
                        'ctx_name': node_data['context_name'],
                        'node': node
                    }
                )
                if 'ret' in node_data and node_data['ret']:
                    tainted_data.append(node_data['ret'])

            if 'args' in node_data and node_data['des'] != 'Start':
                index = 0
                for para in node_data['args'].strip('\n').split('\n'):
                    para = ':'.join(para.split(':')[1:]).strip(' ')
                    if self.tainted(para, tainted_data) and 'rec' in node_data:
                        tainted_subtrace.append(
                            {
                                'type': ARG,
                                'index': index,
                                'rec': node_data['rec'],
                                'sel': node_data['sel'],
                                'data': self.tainted(para, tainted_data),
                                'ea': node_data['addr'],
                                'ctx': node_data['context'],
                                'ctx_name': node_data['context_name'],
                                'node': node
                            }
                        )
                        if 'ret' in node_data and node_data['ret']:
                            tainted_data.append(node_data['ret'])
                        if 'rec' in node_data and node_data['rec']:
                            tainted_data.append(node_data['rec'])
                    index += 1
                continue

            if node in ret_nodes:
                if 'ret' in node_data:
                    if self.tainted(node_data['ret'], tainted_data) and node_data['ret']:
                        tainted_subtrace.append(
                            {
                                'type': RET,
                                'data': self.tainted(node_data['ret'], tainted_data),
                                'ea': node_data['addr'],
                                'ctx': node_data['context'],
                                'ctx_name': node_data['context_name'],
                                'node': node
                            }
                        )
                else:
                    print ""

        self.tainted_subtrace = tainted_subtrace
        return tainted_subtrace

    def tainted(self, data, tainted_data):
        if data in tainted_data:
            return data
        for td in tainted_data:
            # TODO 不准确，且如果出现多个怎么办？ 【这里主要为暂时解决CSEL指令问题】
            if td in data:
                return td


        # if seed.data_type:
        #     if str_to_type(seed.data_type) in self.data_and_ptrs:  # ADT
        #         for ptr in self.data_and_ptrs[str_to_type(seed.data_type)]:
        #             if ptr in self.ea_and_nodes:
        #                 matched_nodes.extend(self.ea_and_nodes[ptr])
        #     for node in self.eTree.nodes:
        #         if 'rec' in self.eTree.nodes[node] and self.eTree.nodes[node]['rec'] == seed.data_type:
        #             matched_nodes.append(node)
        #
        # else:  # API
        #     for node in self.eTree.nodes:
        #         if 'sel' in self.eTree.nodes[node] and self.eTree.nodes[node]['sel'] == seed.selector:
        #             m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)',
        #                           self.eTree.nodes[node]['rec'])
        #             if m and str_to_type(seed.receiver) == m.group('data_type').encode('UTF-8'):
        #                 matched_nodes.append(node)
        #             elif self.eTree.nodes[node]['rec'] == seed.receiver:
        #                 matched_nodes.append(node)


# etree = ETree('/home/gjy/Desktop/results/Privacy/ToGoProject/0x100465e18+[GTXUploadAttachmentFileOperation create:].dot')
# etree.analyze(rec='UIDevice', sel='identifierForVendor')
# etree.query_ret_values()