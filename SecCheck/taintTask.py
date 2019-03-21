# coding=utf-8
from MachOTest.MachOTask import MachOTask
from SecCheck.seed import API
from Data.CONSTANTS import *
from Data.eTree import *
from Data.OCFunction import *
import networkx as nx
import random
LEVEL_TOP = 5


class TaintTask:

    current_task = None

    def __init__(self, binary_name, rule):
        TaintTask.current_task = self
        self.machoTask = MachOTask('../../samples/{}'.format(binary_name), store=True, visualize=False)
        self.rule = rule

    def get_src_ctxs(self):
        """
        根据敏感数据获得可能产生src的方法。
        :return:
        """
        if self.rule in Rules:
            ctxs = set()
            for rule in Rules[self.rule]:
                delegate_protocol = self.resolve_delegate(rule['Receiver'])
                if delegate_protocol:
                    ctxs.update(self.find_protocol_meth(delegate_protocol))
                else:
                    ctxs.update(API(receiver=rule['Receiver'], selector=rule['Selector']).find_calls())
            return ctxs
        else:
            print "{}相关规则不存在。".format(self.rule)
            return None

    def run(self):
        if self.rule in Rules:
            # 一类规则里可能有多条规则，每条规则的类型有两种可能：API或者作为参数的ADT
            for rule in Rules[self.rule]:
                delegate_protocol = self.resolve_delegate(rule['Receiver'])
                if delegate_protocol:
                    for f in self.find_protocol_meth(delegate_protocol):
                        eTree_dot = self.machoTask.analyze_function(start_addr=f)
                        if eTree_dot:
                            traces = ETree(eTree_dot).analyze(as_parameter=1)
                else:
                    for f in API(receiver=rule['Receiver'], selector=rule['Selector']).find_calls():
                        if f != 0x0100471650:
                            continue
                        eTree_dot = self.machoTask.analyze_function(start_addr=f)
                        if eTree_dot:
                            traces = ETree(eTree_dot).analyze(rec=rule['Receiver'], sel=rule['Selector'])
                            for t in traces:
                                if t.tainted_subtrace:
                                    tainted_trace = TaintedTrace(self.rule, t)
                                    tainted_trace.track()
        else:
            print "{}相关规则不存在。".format(self.rule)
            return None

    def resolve_delegate(self, str):
        if '<' in str:
            return str.strip('<>')
        else:
            return None

    def find_protocol_meth(self, protocol):
        return []

    @staticmethod
    def main_test():
        analyzer = TaintTask('ToGoProject', 'ID')
        analyzer.run()


class TaintedTrace:

    def __init__(self, rule, trace):
        self.rule = rule
        self.src = None
        self.init_trace = trace
        self.tracked_trace = nx.DiGraph()

        if trace.tainted_subtrace[0]['type'] == GEN_API:
            self.src = self.add_node(trace.tainted_subtrace[0], 0)
        else:
            print 'ERROR: THE FIRST NODE OF TAINTED TRACE IS NOT GENERATOR.'
        self.build_intra_conn(self.init_trace.tainted_subtrace, self.src, 0)

    def build_intra_conn(self, tainted_sub_trace, start, level):
        if start in self.tracked_trace.nodes:
            pnode = start
            for node in tainted_sub_trace[1:]:
                _node = self.add_node(node, level, add_node_label=self.tracked_trace.nodes[start]['node_label'])
                self.tracked_trace.add_edge(pnode, _node)
                pnode = _node

    def add_node(self, node_data, level, add_node_label=None, data_transferred=None):
        """

        :param node_data: 为eTree中节点的数据
        :param level: 当前节点的level
        :param type: 当前节点的类型
        :return:
        """
        if node_data['type'] == GEN_API:
            des = 'GEN {} \n by invoke [{} {}]\n at {} ({}) \n {}'.format(node_data['data'], node_data['rec'],
                                                                          node_data['sel'], hex(int(node_data['ea'])), node_data['ctx_name'],
                                                                          add_node_label)
            self.tracked_trace.add_node(des, color='green')

        if node_data['type'] == GEN_PARA:
            des = 'GEN {} \n as parameter at {} ({}) \n {}'.format(node_data['data'], hex(int(node_data['ea'])),
                                                                   node_data['ctx_name'], add_node_label)
            self.tracked_trace.add_node(des, color='green')

        if node_data['type'] == ARG:
            des = 'USE {} as argument \n at {} [{} {}] \n {}'.format(node_data['data'], hex(int(node_data['ea'])),
                                                                 node_data['rec'], node_data['sel'], add_node_label)
            self.tracked_trace.add_node(des)

        if node_data['type'] == REC:
            des = 'USE {} as receiver \n at {} [{} {}] \n {}'.format(node_data['data'], hex(int(node_data['ea'])),
                                                                 node_data['rec'], node_data['sel'], add_node_label)
            self.tracked_trace.add_node(des)

        if node_data['type'] == RET:
            des = 'RET {}\n at {} ({}) \n {}'.format(node_data['data'], hex(int(node_data['ea'])), node_data['ctx_name'],
                                                     add_node_label)
            self.tracked_trace.add_node(des, color='blue')

        self.tracked_trace.add_node(des, data=node_data['data'], ori_node=node_data['node'], type=node_data['type'],
                                    ctx=int(node_data['ctx']), ctx_name=node_data['ctx_name'], level=level,
                                    node_label=add_node_label)
        return des

    def find_usage(self, src_node):
        """
        根据任意一个节点，查找其使用。根据敏感数据在该节点中的使用方式不同，该节点的处理方式也不同。
        :param src_node:
        :return:
        """
        src_type = self.tracked_trace.nodes[src_node]['type']
        src_ctx = self.tracked_trace.nodes[src_node]['ctx']
        current_level = self.tracked_trace.nodes[src_node]['level']
        data_transferred = self.tracked_trace.nodes[src_node]['data']
        if src_type == ARG:
            # 当隐私数据作为参数，那么其使用者只可能是使用隐私数据的调用，且该调用中所匹配的隐私数据源只可能是GEN_PARA
            # for imp in find_possible_imp(src):  # should consider parameter index also.
            #     eTree_dot = TaintTask.current_task.machoTask.analyze_function(start_addr=imp)
            #     self.analyze_etree(eTree_dot, src['level'], as_parameter=src['index'])
            pass

        elif src_type == RET:
            # 当隐私数据作为返回值，那么其使用者只可能是当前方法的调用者，且调用者中所匹配的隐私数据源只可能是GEN_API
            if src_ctx in OCFunction.oc_function_set:
                src_f = OCFunction.oc_function_set[src_ctx]
                for caller in API(receiver=src_f.receiver, selector=src_f.selector).find_calls(gist='ADJ'):
                    eTree = TaintTask.current_task.machoTask.analyze_function(start_addr=caller)
                    for des_node in self.analyze_etree(eTree, current_level+1, data_transferred, random.uniform(0, 100),
                                                       generator={
                                                           'AS_PARA': None,
                                                           'AS_API_RET': {'rec': src_f.receiver, 'sel': src_f.selector}
                                                       }):
                        self.tracked_trace.add_edge(src_node, des_node,
                                                    label='return {}'.format(data_transferred), color='red')
            elif src_ctx in OCFunction.meth_list:
                # 如果为subroutine，则需要查找引用。但这样对吗？subroutine有返回值？
                # for caller in XrefsTo(src['ctx']):
                #     eTree_dot = TaintTask.current_task.machoTask.analyze_function(start_addr=caller)
                #     self.analyze_etree(eTree_dot, src['level'], rec=src_f.receiver, sel=src_f.selector)
                pass

    def analyze_etree(self, eTree_dot, level, data_transferred, src_node, generator=None):
        """

        :param eTree_dot:
        :param level: 当前过程所处的level，该过程内所有节点都为该level
        :param as_parameter:
        :param rec:
        :param sel:
        :return:
        """
        start_nodes = []
        if eTree_dot:
            if generator['AS_PARA']:
                pass
            elif generator['AS_API_RET']:
                traces = ETree(eTree_dot).analyze(rec=generator['AS_API_RET']['rec'], sel=generator['AS_API_RET']['sel'])
                for t in traces:
                    if t.tainted_subtrace:
                        if t.tainted_subtrace[0]['type'] == GEN_API:
                            start_node = self.add_node(t.tainted_subtrace[0], level, data_transferred=data_transferred,
                                                       add_node_label=src_node)
                            start_nodes.append(start_node)
                            self.build_intra_conn(t.tainted_subtrace, start_node, level)
                        else:
                            print 'ERROR: THE FIRST NODE OF TAINTED TRACE IS NOT GENERATOR.'
        return start_nodes

    def sink(self, usage_node):
        usage_info = self.tracked_trace.nodes[usage_node]
        if 'NSURLConnection' in usage_info['rec'] and 'start' == usage_info['sel']:
            pass


    def track(self):
        print 'Track'
        level = 0
        while True:
            if level == LEVEL_TOP:
                break
            to_be_analyzed = []
            for node in self.tracked_trace.nodes:
                if self.tracked_trace.nodes[node]['level'] == level:
                    to_be_analyzed.append(node)
            if not to_be_analyzed:
                break
            for node in to_be_analyzed:
                self.find_usage(node)
            level += 1
        fp = '/home/gjy/Desktop/results/tainted_traces/{}/{}.dot'.format(LEVEL_TOP, self.tracked_trace.nodes[self.src]['ctx_name'])
        try:
            nx.drawing.nx_agraph.write_dot(self.tracked_trace, fp)
            return fp
        except Exception as e:
            print 'Failed to generate {}, {} '.format(fp, e)
            return None



TaintTask.main_test()

