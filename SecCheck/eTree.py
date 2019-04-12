# coding=utf-8

import networkx as nx
import copy
import chardet
from tools.TypeInfer import TypeInfer
from tools.common import *
from Data.OCClass import OCClass
from Data.OCFunction import OCFunction
from MachOTask import MachOTask

RET = 'as return value'
REC = 'as receiver'
ARG = 'as argument'
GEN_REC = 'as receiver'
GEN_PARA = 'as parameter'
GEN_API = 'as generator'

UNDEF = None
IMPORTED = 0

FAILED_TO_UPDATE_NODE = 0
AS_RECEIVER = -1


class ETree:

    def __init__(self, etree_file):
        self.eTree = nx.drawing.nx_agraph.read_dot(etree_file)
        self.start_node = self.eTree.graph['start']
        self.ret_nodes = eval(self.eTree.graph['ret'])
        self.traces = []

    @staticmethod
    def get_handler(etree_file=None, start_ea=None):
        if start_ea:
            eTree_dot = MachOTask.currentTask.analyze_function(start_addr=start_ea)
            if eTree_dot and os.path.exists(eTree_dot):
                return ETree(eTree_dot)
        elif etree_file and os.path.exists(etree_file):
            return ETree(etree_file)
        return None

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

    def query_ret_values(self, limits=None):
        """
        执行树的返回值为数据，因此重点就是数据的类型判定；
        方法的返回值通常来自于 1）方法过程内的某次调用结果，或者是来自2）直接引用的数据，或者是3）参数；
        当为1）时，类型有大比例会不确定。
        :param limits:当返回值有多种类型时，可以根据后续该对象可以处理的selector消息来进行类型推断。
        :return:
        """
        ret_data_type = dict()
        sel_limits = []
        for limit in limits:
            sel_limits.append(limit[1]) if limit[0] == 'SEL' else None

        # PLAN A: 对每一个返回值节点，如果该数据实现了selector，那么作为备选项；否则淘汰。
        for node in self.ret_nodes:
            data_type, instance_type, ptr = symbol_resolved(self.eTree.nodes[node]['ret'])
            if data_type and data_type not in ret_data_type:
                f = OCClass.retrieve_func(rec=data_type, sel=sel_limits[0])
                if f is UNDEF:
                    pass
                elif f is IMPORTED:
                    add_value_to_list_in_dict_with_key(node, data_type, ret_data_type)
                elif type(f) == OCFunction:
                    add_value_to_list_in_dict_with_key(node, data_type, ret_data_type)
        return ret_data_type

    def taint_analyze(self, rec=None, sel=None, as_parameter=None, rule=None, data_transferred=None):
        if not self.traces:
            self.traverse()
        tainted_traces = []
        bak_tainted = []
        for trace in self.traces:
            trace.taint_analyze(rec=rec, sel=sel, as_parameter=as_parameter, rule=rule, data_transferred=data_transferred)
            if len(trace.tainted_subtrace) > 1:
                if trace.tainted_subtrace in bak_tainted:
                    continue
                bak_tainted.append(trace.tainted_subtrace)
                tainted_traces.append(trace)
        return tainted_traces


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

        self.tainted_subtrace = None  # 该路径中被污染的子路径，可能有多条（有多个匹配的起始节点）
        self.ea_node = dict()  # 该路径中 地址-节点 的映射字典

    def terminate(self):
        self.alive = False
        Trace.alive_traces.remove(self)
        Trace.deadend_traces.append(self)

    def step(self):
        out_edges = self.tree.out_edges(self.route[-1])
        if len(out_edges) == 0:
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

    def taint_analyze(self, rec=None, sel=None, as_parameter=None, rule=None, data_transferred=None):
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
            node_data = self.tree.nodes[start_node]
            if as_parameter == AS_RECEIVER:
                tainted_data.append(node_data['rec'])
                tainted_subtrace.append(
                    {
                        'type': GEN_REC,
                        'data': node_data['rec'],
                        'node': start_node,
                        'index': as_parameter
                    }
                )

            else:  # as custom parameter
                if 'args' in node_data:
                    tainted_data.append(eval(node_data['args'])[as_parameter])
                    tainted_subtrace.append(
                        {
                            'type': GEN_PARA,
                            'data': eval(node_data['args'])[as_parameter],
                            'node': start_node,
                            'index': as_parameter
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
                                'data': node_data['ret'],
                                'node': node
                            }
                        )
                        tainted_data.append(node_data['ret'])

            if 'rec' in node_data and self.tainted(node_data['rec'], tainted_data):
                tainted_subtrace.append(
                    {
                        'type': REC,
                        'index': AS_RECEIVER,
                        'data': self.tainted(node_data['rec'], tainted_data),
                        'node': node
                    }
                )
                if 'ret' in node_data and node_data['ret']:
                    tainted_data.append(node_data['ret'])

            if 'args' in node_data and node_data['des'] != 'Start':
                index = 0
                for para in eval(node_data['args']):
                    # para = ':'.join(para.split(':')[1:]).strip(' ')
                    if self.tainted(para, tainted_data) and 'rec' in node_data:
                        tainted_subtrace.append(
                            {
                                'type': ARG,
                                'index': index,
                                'data': self.tainted(para, tainted_data),
                                'node': node
                            }
                        )
                        if 'ret' in node_data and node_data['ret']:
                            tainted_data.append(node_data['ret'])
                        if 'rec' in node_data and node_data['rec']:
                            tainted_data.append(node_data['rec'])
                    index += 1

            if node in ret_nodes:
                if 'ret' in node_data:
                    if self.tainted(node_data['ret'], tainted_data) and node_data['ret']:
                        tainted_subtrace.append(
                            {
                                'type': RET,
                                'data': self.tainted(node_data['ret'], tainted_data),
                                'node': node
                            }
                        )
                else:
                    print ""

        self.tainted_subtrace = tainted_subtrace
        return tainted_subtrace

    def tainted(self, data, tainted_data):
        if data:
            try:
                if type(data) == str:
                    encoding = chardet.detect(data)['encoding']
                    data = data.decode(encoding).encode('utf-8')  # TODO: 对从dot文件中解析出来的数据统一做编码处理
                if data in tainted_data:
                    return data
                for td in tainted_data:
                    # TODO 不准确，且如果出现多个怎么办？ 【这里主要为暂时解决CSEL指令问题】
                    if td in data:
                        return td
            except UnicodeDecodeError as e:
                print 'ERROR 7: {}'.format(e)

    def update_node(self, node):
        """
        node为eTree中一节点，该节点信息(receiver)依赖于前文节点，因此在此更新，根据信息需求可能会迭代更新前文节点。
        :param node:
        :return:
        """
        node_data = self.tree.nodes[node]
        if 'rec_dpr' not in node_data or not eval(node_data['rec_dpr']):
            return FAILED_TO_UPDATE_NODE

        dp_node_ea = int(eval(node_data['rec_dpr']).keys()[0].strip('L'), 16)
        dp_type = eval(node_data['rec_dpr']).values()[0]
        if dp_node_ea not in self.ea_node:
            return FAILED_TO_UPDATE_NODE
        else:
            dp_node = self.ea_node[dp_node_ea]

        if dp_type == 'RET':
            if type(eval(dp_node['handler'])) != int:  # 'TODO: 被依赖节点类型不确定，需要再向上？'
                print '被依赖节点类型不确定，需再向上更新。'
                return FAILED_TO_UPDATE_NODE
            execution_tree_of_dp_node = ETree.get_handler(start_ea=eval(dp_node['handler']))
            if not execution_tree_of_dp_node:
                return FAILED_TO_UPDATE_NODE
            ret_values = execution_tree_of_dp_node.query_ret_values(limits=[('SEL', node_data['sel'])])
            if len(ret_values) > 1:
                print "TODO: 在更新节点时，即使使用selector进行限制，也有多种可能性，怎么解决。（可以考虑使用路径约束）"
            for ret in ret_values:
                current_method = OCClass.retrieve_func(rec=ret, sel=node_data['sel'])
                if current_method:
                    node_data['handler'].append(current_method.imp)
                    # UPDATE: 将当前节点的REC_TYPE, RET_TYPE, handler都修改,但出现多个匹配怎么办？
                    # TODO：那有没有资格改上个节点的信息？没有资格去改上文节点的eTree，但有资格改TaintedTrace中的上文节点，约束路径。
                    print 'T'
        elif dp_type == 'GEN_PARA':
            args = eval(dp_node['args'])
            index = args.index(node_data['rec']) if node_data['rec'] in args else None
            if index is not None:
                if 'temp_para' in self.tree.nodes[self.tree.graph['start']]:
                    pass

        elif dp_type == 'IVAR':
            pass
        else:
            pass


