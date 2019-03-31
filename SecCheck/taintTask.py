# coding=utf-8
from MachOTest.MachOTask import MachOTask
from SecCheck.seed import API
from Data.CONSTANTS import *
from Data.eTree import *
from Data.OCFunction import *
from Data.OCClass import *
from Data.data import *
from tools.oc_type_parser import *
import networkx as nx
import random

LEVEL_TOP = 4


class TaintTask:
    current_task = None

    def __init__(self, binary_name, rule):
        TaintTask.current_task = self
        self.machoTask = MachOTask('../../samples/{}'.format(binary_name), store=True, visualize=False)
        self.rule = rule

    @staticmethod
    def main_test():
        analyzer = TaintTask('ToGoProject', 'ID')
        analyzer.run()

    def run(self):
        if self.rule in Rules:
            for rule in Rules[self.rule]:
                to_be_analyzed = set()
                if rule['Type'] == AS_PROTO_METH_PARA:
                    for f in OCFunction.find_protocol_method(rule['Receiver'], rule['Selector']):
                        to_be_analyzed.add(f)
                else:
                    for f in API(receiver=rule['Receiver'], selector=rule['Selector']).find_calls():
                        to_be_analyzed.add(f)

                for f in to_be_analyzed:
                    if f != 0x10034594C:
                        continue
                    eTree_dot = self.machoTask.analyze_function(start_addr=f)
                    if eTree_dot:
                        for trace in ETree(eTree_dot).traverse():
                            if trace.taint_analyze(rule=rule):
                                tainted_trace = TaintedTrace(self.rule, trace)
                                tainted_trace.track()
        else:
            print "{}相关规则不存在。".format(self.rule)
            return None


class TaintedTrace:

    def __init__(self, rule, trace):
        """
        一条完整的污染路径，由预定义的level进行扩展。
        :param rule:
        :param trace: 初始化路径，Trace对象，level为0.
        """
        self.rule = rule
        self.init_trace = trace
        self.tracked_trace = nx.DiGraph()
        self.node_and_trace = dict()

        if trace.tainted_subtrace[0]['type'] == GEN_API:
            self.src = self.add_node(trace.tainted_subtrace[0], 0, trace, node_label=random.uniform(0, 100))
            self.build_intra_conn(self.init_trace.tainted_subtrace, self.src)
        else:
            print 'ERROR: THE FIRST NODE OF TAINTED TRACE IS NOT A GENERATOR.'

    def build_intra_conn(self, tainted_sub_trace, start):
        """
        将tainted_sub_trace中的节点添加到TaintedTrace中
        :param tainted_sub_trace:
        :param start:
        :return:
        """
        if start in self.tracked_trace.nodes:
            current_level = self.tracked_trace.nodes[start]['level']
            current_label = self.tracked_trace.nodes[start]['node_label']
            current_trace = self.node_and_trace[start]
            pnode = start
            for node in tainted_sub_trace[1:]:
                _node = self.add_node(node, current_level, current_trace, node_label=current_label)
                self.tracked_trace.add_edge(pnode, _node)
                pnode = _node

    def add_node(self, node_data, level, trace, node_label=None, data_transferred=None):
        """

        :param node_data: 为eTree中节点的数据
        :param level: 当前节点的level
        :param trace: 该节点作为路径（Trace 对象）
        :return:
        """
        if node_data['type'] == GEN_API:
            des = 'GEN {} \n by invoke [{} {}]\n at {} ({}) \n {}'.format(node_data['data'], node_data['rec'],
                                                                          node_data['sel'], hex(int(node_data['ea'])),
                                                                          node_data['ctx_name'], node_label)
            self.tracked_trace.add_node(des, color='green')

        if node_data['type'] == GEN_PARA:
            des = 'GEN {} \n as parameter at {} ({}) \n {}'.format(node_data['data'], hex(int(node_data['ea'])),
                                                                   node_data['ctx_name'], node_label)
            self.tracked_trace.add_node(des, color='green')

        if node_data['type'] == ARG:
            des = 'USE {} as argument \n at {} [{} {}] \n {}'.format(node_data['data'], hex(int(node_data['ea'])),
                                                                     node_data['rec'], node_data['sel'], node_label)

        if node_data['type'] == REC:
            des = 'USE {} as receiver \n at {} [{} {}] \n {}'.format(node_data['data'], hex(int(node_data['ea'])),
                                                                     node_data['rec'], node_data['sel'], node_label)

        if node_data['type'] == RET:
            des = 'RET {}\n at {} ({}) \n {}'.format(node_data['data'], hex(int(node_data['ea'])),
                                                     node_data['ctx_name'],
                                                     node_label)
            self.tracked_trace.add_node(des, color='blue')

        self.tracked_trace.add_node(des, node_data=node_data, node_label=node_label, level=level)

        if str(level) in self.tracked_trace.graph:
            self.tracked_trace.graph[str(level)].add(des)
        else:
            self.tracked_trace.graph[str(level)] = set([des])

        if des not in self.node_and_trace:
            self.node_and_trace[des] = trace
        else:
            print 'ERROR: 1'

        return des

    def find_usage(self, src_node):
        """
        根据任意一个节点，查找其使用。根据敏感数据在该节点中的使用方式不同，该节点的处理方式也不同。
        :param src_node:
        :return:
        """
        node_data = self.tracked_trace.nodes[src_node]['node_data']
        data_transferred = node_data['data']

        if node_data['type'] == ARG:
            #     rec = node_data['rec']
            #     sel = node_data['sel']
            #     if Data.decode(rec):
            #         receiver_info = Data.decode(rec)
            #         data_type = type_to_str(receiver_info[0])
            #         if data_type == 'unknown':
            #             print "BACK TRACK HERE."
            #         rec = data_type
            #     if rec in OCClass.classes_indexed_by_name and not OCClass.classes_indexed_by_name[rec][0].imported:
            #         func = OCClass.retrieve_func(rec=rec, sel=sel)
            #     if Frameworks.query(node_data['rec'], node_data['sel']):
            #         return  # BUT SINK MAY BE CHECKED HERE.
            node_data_in_etree = self.node_and_trace[src_node].tree.nodes[node_data['node']]
            handler = eval(node_data_in_etree['handler'])
            if type(handler) == int:
                imp = handler
            elif handler is None:
                return
            else:
                print 'T'
                imp = None
            self.track_usage(src_node, imp, data_transferred,
                             generator={
                                 'AS_PROTO_METH_PARA': node_data['index'],
                                 'AS_API_RET': None
                             })

        elif node_data['type'] == RET:
            if int(node_data['ctx']) in OCFunction.oc_function_set:
                src_f = OCFunction.oc_function_set[int(node_data['ctx'])]
                for caller in API(receiver=src_f.receiver, selector=src_f.selector).find_calls(gist='ADJ'):
                    self.track_usage(src_node, caller, data_transferred,
                                     generator={
                                         'AS_PROTO_METH_PARA': None,
                                         'AS_API_RET': {'rec': src_f.receiver, 'sel': src_f.selector}
                                     })
            elif node_data['ctx'] in OCFunction.meth_list:
                # 如果为subroutine，则需要查找引用。但这样对吗？subroutine有返回值？
                # for caller in XrefsTo(src['ctx']):
                pass

    def track_usage(self, src, func, data_transferred, generator=None):
        """
        :param func:
        :param level: 当前过程所处的level，该过程内所有节点都为该level
        :return:
        """
        # TODO 如果func与src同一ctx？

        eTree_dot = TaintTask.current_task.machoTask.analyze_function(start_addr=func)
        if eTree_dot:

            current_level = self.tracked_trace.nodes[src]['level'] + 1

            if generator['AS_PROTO_METH_PARA'] is not None:
                print 'T'
                for trace in ETree(eTree_dot).traverse():
                    trace.taint_analyze(as_parameter=generator['AS_PROTO_METH_PARA'])
                    if trace.tainted_subtrace and trace.tainted_subtrace[0]['type'] == GEN_PARA:
                        des = self.add_node(trace.tainted_subtrace[0], current_level, trace,
                                            data_transferred=data_transferred,
                                            node_label=random.uniform(0, 100))
                        self.build_intra_conn(trace.tainted_subtrace, des)
                        self.tracked_trace.add_edge(src, des, color='red')

            elif generator['AS_API_RET']:
                for trace in ETree(eTree_dot).traverse():
                    trace.taint_analyze(rec=generator['AS_API_RET']['rec'], sel=generator['AS_API_RET']['sel'])
                    if trace.tainted_subtrace and trace.tainted_subtrace[0]['type'] == GEN_API:
                        des = self.add_node(trace.tainted_subtrace[0], current_level, trace,
                                            data_transferred=data_transferred,
                                            node_label=random.uniform(0, 100))
                        self.build_intra_conn(trace.tainted_subtrace, des)
                        self.tracked_trace.add_edge(src, des, color='blue')

    def track(self):
        level = 0
        while True:
            if level == LEVEL_TOP or str(level) not in self.tracked_trace.graph:
                break
            for node in self.tracked_trace.graph[str(level)]:
                self.find_usage(node)
            level += 1

        fp = '/home/gjy/Desktop/results/tainted_traces/{}/{}_{}.dot'.format(
            LEVEL_TOP, self.tracked_trace.nodes[self.src]['node_data']['ctx_name'], random.random())
        try:
            nx.drawing.nx_agraph.write_dot(self.tracked_trace, fp)
        except Exception as e:
            print 'Failed to generate {}, {} '.format(fp, e)


TaintTask.main_test()
