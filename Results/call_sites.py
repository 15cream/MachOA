# coding=utf-8
import re
import os
import pickle
import networkx as nx
from Data.MachO import MachO
"""
CallSite用于记录方法调用时的具体调用细节。
在符号执行的任何阶段，当需要记录一个callsite的信息时，创建CallSite对象并将其添加到result_pool中，
每当执行一个方法调用时，首先检验该调用特征是否存在于result_pool，若是，则解析调用信息并更新对象。
当调用特征越具体时，越不容易出现碰撞。【就不需要考虑是使用list还是更新覆盖的问题】
还可以通过特征来指定需要做的具体安全检测。
"""


class CallSite:

    result_pool = dict()  # indexed by id
    result_pool_indexed_by_caller = dict()

    def __init__(self, callee, ctx, id=None, criterion=None):
        self.callee = callee
        self.caller_ctx = ctx
        self.criterion = criterion
        self.id = id
        self.sites = dict()  # Indexed by call_site address
        self.graph = None  # graph也由caller与callee唯一确定；即可由id唯一标识。

    @staticmethod
    def add(callee, ctx, criterion=None):
        if criterion:
            id = "{}_{}".format(ctx, criterion)
        else:
            id = "{}_{}".format(ctx, callee)
        if id not in CallSite.result_pool:
            r = CallSite(callee, ctx, id=id, criterion=criterion)
            CallSite.result_pool[id] = r
            if ctx not in CallSite.result_pool_indexed_by_caller:
                CallSite.result_pool_indexed_by_caller[ctx] = [r, ]
            else:
                CallSite.result_pool_indexed_by_caller[ctx].append(r)
            return id
        else:
            return None

    def analyze_results_according_to_criterion(self):
        constants = {}
        symbols = {}
        for msg in self.sites:
            sensitive_arg_index = self.criterion[2]
            arg_data = msg.selector.args[sensitive_arg_index]
            if arg_data.concrete:
                constants[arg_data.expr] = msg
            else:
                symbols[arg_data.expr] = msg
        return constants, symbols

    @staticmethod
    def collect(graphview, node):
        # 不受当前的callString限制，只要caller与callee唯一确定即可
        node_data = graphview.g.nodes[node]
        if 'handler' not in node_data:
            return
        if node_data['context'] in CallSite.result_pool_indexed_by_caller:
            r_list = CallSite.result_pool_indexed_by_caller[node_data['context']]
            rr = None
            for r in r_list:
                if r.callee and node_data['handler'] == r.callee:
                    rr = r
                    break
                elif r.criterion:
                    if node_data['sel'] and node_data['sel'] in r.criterion:
                        rr = r
                        break
            if not rr:
                return
            if rr.graph is None:
                rr.graph = graphview
            if node_data['addr'] in rr.sites:
                rr.sites[node_data['addr']].append(node)
            else:
                rr.sites[node_data['addr']] = [node, ]
        else:
            return

    @staticmethod
    def dump():
        for id, r in CallSite.result_pool.items():
            dir = '{}{}'.format(MachO.pd.task.configs.get('PATH', 'results'), MachO.pd.macho.provides)
            fname = '{}/cs_limited/{}'.format(dir, r.id)
            try:
                if r.graph and type(r.graph) is not str:
                    nx.drawing.nx_agraph.write_dot(r.graph.g, fname + '.dot')
                output = open(fname+'.pkl', 'wb')
                r.graph = fname + '.dot'
                r.result_pool = None
                r.result_pool_indexed_by_caller = None
                pickle.dump(r, output)
                output.close()
            except Exception as e:
                print 'Failed to generate {}, {} '.format(fname, e)

    @staticmethod
    def restore():
        dir = '{}{}/cs_limited'.format(MachO.pd.task.configs.get('PATH', 'results'), MachO.pd.macho.provides)
        for f in os.listdir(dir):
            if f.split('.')[-1] == 'pkl':
                caller = f.split('_')[0]
                input = open(os.path.join(dir, f), 'rb')
                r = pickle.load(input)
                input.close()
                if r.id not in CallSite.result_pool:
                    CallSite.result_pool[r.id] = r
                    if caller not in CallSite.result_pool_indexed_by_caller:
                        CallSite.result_pool_indexed_by_caller[caller] = [r, ]
                    else:
                        CallSite.result_pool_indexed_by_caller[caller].append(r)
                    # r.result_pool = CallSite.result_pool  # is it necessary
                else:
                    pass
            elif f.split('.')[-1] == 'dot':
                pass


