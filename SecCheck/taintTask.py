# coding=utf-8
from MachOTest.MachOTask import MachOTask
from SecCheck.seed import API
from Data.CONSTANTS import *
import networkx as nx


class TaintAnalyzer:

    def __init__(self, binary_name, data):
        self.machoTask = MachOTask('../../samples/{}'.format(binary_name), store=True, visualize=False)
        self.data = data

    def run(self):
        """
        对每个需要解析的方法初始化后，首先进行一次标记。例如，当参数为敏感数据时。
        :return:
        """
        for f in self.get_src_ctxs():
            ret = self.machoTask.analyze_function(start_addr=f)
            print '{}: {}'.format(hex(f), ret)

    def get_src_ctxs(self):
        """
        根据敏感数据获得可能产生src的方法。
        :return:
        """
        if self.data in Rules:
            ctxs = set()
            for rule in Rules[self.data]:
                delegate_protocol = self.resolve_delegate(rule['Receiver'])
                if delegate_protocol:
                    ctxs.update(self.find_protocol_meth(delegate_protocol))
                else:
                    ctxs.update(API(receiver=rule['Receiver'], selector=rule['Selector']).find_calls())
            return ctxs
        else:
            print "{}相关规则不存在。".format(self.data)
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
        analyzer = TaintAnalyzer('ToGoProject', 'ID')
        analyzer.run()


TaintAnalyzer.main_test()


class TaintTrace:

    def __init__(self):
        self.data_type = None
        self.traces = nx.DiGraph()
        self.src = None

    def add_usage(self):
        pass


class TaintNode:

    def __init__(self, data, type, ctx, ea):
        """

        :param data: 该点的数据符号表示（可能是被处理后的数据表示）
        :param type: SRC（根据预定义API定位的数据）/RET(被标记的数据作为返回值)/SINK（被标记数据作为预定义sink的数据参数）/
        Processed(数据处理，当被标记数据作为调用的参数时，默认为处理，其实sink也算处理的一种，)
        :param ctx:　
        :param ea:　
        """
        self.data = data
        self.type = type
        self.ctx = ctx
        self.ea = ea
