# coding=utf-8
from SecCheck.seed import API
from SecCheck.eTree import *
from Data.OCFunction import *
from Data.OCivar import IVar
from Data.data import *
import networkx as nx
import random
import sys
import commands

from RuntimePatch.frameworks.Foundation.NSData import NSData
from RuntimePatch.frameworks.Foundation.Networking import *


class TaintTask:

    current_task = None

    def __init__(self, binary_path, rule_ID):
        self.machoTask = MachOTask(binary_path, store=True, visualize=False)
        self.rule_id = rule_ID
        TaintTask.current_task = self

    def run(self):
        if self.rule_id not in Rules:
            print "{}相关规则不存在。".format(self.rule_id)
            exit(0)

        for rule in Rules[self.rule_id]:
            to_be_analyzed = set()
            if rule['Type'] == AS_METH_PARA:
                to_be_analyzed.update(OCFunction.find_protocol_method(rule['Protocol'], rule['Selector']))
            else:
                to_be_analyzed.update(API(receiver=rule['Receiver'], selector=rule['Selector']).find_calls())

            for f in to_be_analyzed:
                # if f != 0x10034594C:
                #     continue
                execution_tree = ETree.get_handler(start_ea=f)
                if execution_tree:
                    # for trace in execution_tree.traverse():
                    #     if trace.taint_analyze(rule=rule):
                    #         TaintedTrace(self.rule_id, trace).track()
                    tainted_traces = execution_tree.taint_analyze(rule=rule)
                    for trace in tainted_traces:
                        if trace.tainted_subtrace:
                            TaintedTrace(self.rule_id, trace).track()


class TaintedTrace:

    def __init__(self, rule, trace):
        """
        一条完整的污染路径，由预定义的level进行扩展。
        :param rule:
        :param trace: 初始化路径(Trace对象)，level为0.
        """
        self.rule = rule
        self.init_trace = trace
        self.tracked_trace = nx.DiGraph()
        self.node_and_trace = dict()  # 记录污点（当前图中的表示）与其原本所属的路径（Trace对象）

        taint_generator = trace.tainted_subtrace[0]  # type, data, node, 可能包含index
        self.start_ctx = trace.tree.nodes[taint_generator['node']]['context_name']
        if taint_generator['type'] in [GEN_API, GEN_PARA]:
            self.src = self.add_node(taint_generator, 0, trace, node_label=random.uniform(0, 100))
            self.build_intra_conn(trace.tainted_subtrace, self.src)
        else:
            print 'ERROR: THE FIRST NODE OF TAINTED TRACE IS NOT A GENERATOR.'

    def build_intra_conn(self, tainted_subtrace, start):
        """
        将tainted_sub_trace中的节点添加到TaintedTrace中。
        :param tainted_subtrace:
        :param start:
        :return:
        """
        if start in self.tracked_trace.nodes:
            current_level = self.tracked_trace.nodes[start]['level']
            current_label = self.tracked_trace.nodes[start]['node_label']
            current_trace = self.node_and_trace[start]
            pnode = start
            for node in tainted_subtrace[1:]:
                _node = self.add_node(node, current_level, current_trace, node_label=current_label)
                self.tracked_trace.add_edge(pnode, _node)
                pnode = _node

    def add_node(self, tainted_info, level, trace, node_label=None, data_transferred=None):
        """
        :param tainted_info: 为tainted_subtrace中节点的数据, 通常为{'type': ?; 'data': ?; 'node':?;}，有时会多一个键index。
        :param level: 当前节点的level
        :param trace: 该节点所在路径（Trace对象）
        :return:
        """
        node_data = trace.tree.nodes[tainted_info['node']]
        invoke_str = '({})[{} {}]'.format(hex(int(node_data['addr'])), node_data['rec'], node_data['sel'])
        ctx = node_data['context_name']

        if tainted_info['type'] == GEN_API:
            des = 'GEN {} \n by invoke {} \n ({})\n {}'.format(tainted_info['data'], invoke_str, ctx, node_label)
            self.tracked_trace.add_node(des, color='green')

        if tainted_info['type'] == GEN_PARA:
            des = 'GEN {} \n as No.{} parameter of {} \n {}'.format(tainted_info['data'], tainted_info['index'], ctx, node_label)
            self.tracked_trace.add_node(des, color='green')

        if tainted_info['type'] == ARG:
            des = 'USE {} as argument \n at {} \n {}'.format(tainted_info['data'], invoke_str, node_label)

        if tainted_info['type'] == REC:
            des = 'USE {} as receiver \n at {} \n {}'.format(tainted_info['data'], invoke_str, node_label)

        if tainted_info['type'] == RET:
            des = 'RET {}\n at {} ({}) \n {}'.format(tainted_info['data'], hex(int(node_data['addr'])), ctx, node_label)
            self.tracked_trace.add_node(des, color='blue')

        self.tracked_trace.add_node(des, tainted_info=tainted_info, node_label=node_label, level=level)

        if str(level) in self.tracked_trace.graph:
            self.tracked_trace.graph[str(level)].add(des)
        else:
            self.tracked_trace.graph[str(level)] = set([des])

        if des not in self.node_and_trace:
            self.node_and_trace[des] = trace
        else:
            print 'ERROR: 1'  # 在加随机数的情况下，保证路径敏感，应该不会出现同一路径上同一地址出现多次的状况

        return des

    def find_usage(self, src_node):
        """
        根据任意一个节点，查找其使用。根据敏感数据在该节点中的使用方式不同，该节点的处理方式也不同。
        :param src_node:
        :return:
        """
        tainted_info = self.tracked_trace.nodes[src_node]['tainted_info']
        data_transferred = tainted_info['data']
        node_type = tainted_info['type']
        node_in_etree = tainted_info['node']
        node_data_in_etree = self.node_and_trace[src_node].tree.nodes[node_in_etree]
        ctx = int(node_data_in_etree['context'])

        if node_type in [ARG, REC]:
            handler = eval(node_data_in_etree['handler']) if 'handler' in node_data_in_etree else None
            if type(handler) == int:
                if node_type is REC:
                    self.track_usage(src_node, handler, data_transferred, para_index=tainted_info['index'])
                elif node_type is ARG:
                    # 检测是否作为setter的参数，若是则直接解析getter的调用者
                    getter = IVar.ret_getter_according_to_setter(ea=handler)
                    if getter and getter in OCFunction.oc_function_set:
                        getter = OCFunction.oc_function_set[getter]
                        for caller in API(receiver=getter.receiver, selector=getter.selector).find_calls(gist='ADJ'):
                            self.track_usage(src_node, caller, data_transferred, rec=getter.receiver, sel=getter.selector)
                    else:
                        self.track_usage(src_node, handler, data_transferred, para_index=tainted_info['index'])

            elif handler is None:
                self.node_and_trace[src_node].update_node(node_in_etree)
                if self.is_sink(node_data_in_etree):
                    print 'FOUND SINK: {}'.format(src_node)
            else:
                if handler is EMPTY_LIST:
                    self.node_and_trace[src_node].update_node(node_in_etree)
                updated_handlers = eval(node_data_in_etree['handler'])
                for imp in updated_handlers:
                    self.track_usage(src_node, imp, data_transferred, para_index=tainted_info['index'])

        elif node_type == RET:
            if ctx in OCFunction.oc_function_set:
                src_f = OCFunction.oc_function_set[ctx]
                if src_f.ret_type.startswith('v'):
                    return
                for caller in API(receiver=src_f.receiver, selector=src_f.selector).find_calls(gist='ADJ'):
                    self.track_usage(src_node, caller, data_transferred, rec=src_f.receiver, sel=src_f.selector)
            elif ctx in OCFunction.meth_list:  # TODO: subroutine
                # for caller in XrefsTo(caller_ctx):
                pass

    def is_sink(self, node_data_in_etree):
        selector = node_data_in_etree['sel']
        if NSData.is_writing_action(sel=selector):
            return True
        if NSURLSession.is_upload_task(sel=selector):
            return True
        if NSURLRequest.is_HTTPBody(sel=selector) or NSMutableURLRequest.is_HTTPBody(sel=selector):
            return True
        return False

    def track_usage(self, src, func, data_transferred, para_index=None, rec=None, sel=None):
        """
        跟踪一个数据的使用，该数据来自于src节点，目前猜测被用在了func里，具体传递的数据为data_transferred。
        :param src:
        :param func:
        :param data_transferred:
        :param para_index:
        :param rec:
        :param sel:
        :return:
        """
        if eval(self.node_and_trace[src].tree.nodes[self.node_and_trace[src].route[0]]['context']) == func:
            return  # TODO 如果func与src同一context，则跳过。这里逻辑需要再考虑下。
        execution_tree = ETree.get_handler(start_ea=func)
        if not execution_tree:
            return  # 该污点数据追踪不可行

        execution_tree.eTree.nodes[execution_tree.start_node]['temp_para'] = eval(self.node_and_trace[src].tree.nodes[self.tracked_trace.nodes[src]['tainted_info']['node']]['args'])
        current_level = self.tracked_trace.nodes[src]['level'] + 1
        if para_index is not None:
            tainted_traces = execution_tree.taint_analyze(as_parameter=para_index, data_transferred=data_transferred)
            for trace in tainted_traces:
                if trace.tainted_subtrace and trace.tainted_subtrace[0]['type'] == GEN_PARA:
                    des = self.add_node(trace.tainted_subtrace[0], current_level, trace,
                                        data_transferred=data_transferred,
                                        node_label=random.uniform(0, 100))
                    self.build_intra_conn(trace.tainted_subtrace, des)
                    self.tracked_trace.add_edge(src, des, color='red')

        elif rec and sel:
            tainted_traces = execution_tree.taint_analyze(rec=rec, sel=sel, data_transferred=data_transferred)
            for trace in tainted_traces:
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

        fp = '/home/gjy/Desktop/results/tainted_traces/{}/{}_{}.dot'.format(LEVEL_TOP, self.start_ctx, random.random())
        try:
            nx.drawing.nx_agraph.write_dot(self.tracked_trace, fp)
        except Exception as e:
            print 'Failed to generate {}, {} '.format(fp, e)


# binary_path = sys.argv[1]
# RULE_NAME = sys.argv[2]
binary_path = '/home/gjy/Desktop/samples/yellowpage_arm64'
RULE_NAME = 'ID'
# 关于设置数据引用的层级；每一层扩展，都意味着数据的引用。设置这个限制的原因，主要是考虑到效率，路径长度（PiOS中也有类似的考量），
# 以及越外层的数据，事实上被处理得越面目全非 = ， =
LEVEL_TOP = 7
if os.path.exists(binary_path):
    if RULE_NAME in Rules:
        analyzer = TaintTask(binary_path, RULE_NAME)
        analyzer.run()
    else:
        print "规则名不存在"
else:
    print '文件路径不存在'