# coding=utf-8
from seed import *
import copy
from RuntimePatch.ExecutionLimitation import CLimitation
from Results.call_sites import CallSite
"""
在callString的设计时，也考虑过是否要拆分
"""


class CallString:

    current_cs = None

    def __init__(self, API):
        self.stack = [API, ]
        self.seed = API
        self.extra = dict()

    def copy(self):
        cs_copy = CallString(self.seed)
        cs_copy.stack = copy.deepcopy(self.stack)
        cs_copy.extra = copy.deepcopy(self.extra)
        return cs_copy

    def copy_and_add(self, method):
        cs_copy = self.copy()
        # 避免循环调用(其实是允许在callString中出现同一个方法的，但这样逻辑就更复杂了)
        for c in cs_copy.stack:
            if c.description == method.description:
                return None
        cs_copy.stack.append(method)
        return cs_copy

    def add_constraints(self, caller_ctx, callee, info):
        self.extra[(caller_ctx, callee)] = info

    @staticmethod
    def construct_according_to_a_seed(seed):

        ret = []
        init_cs = CallString(seed)
        tmp = [init_cs, ]

        while tmp:
            dele = []
            add = []
            for cs in tmp:
                callee = cs.stack[-1]
                callers = callee.find_calls_with_detail()
                if not callers:  # TODO event handler的隐式调用
                    ret.append(cs)
                else:
                    for caller_ctx, caller_info in callers.items():
                        meth = API(ea=caller_ctx)
                        new_cs = cs.copy_and_add(meth) or None
                        if new_cs and new_cs not in add:  # TODO 应该不是对象而是内容
                            new_cs.add_constraints(meth.ea, callee.ea, caller_info)
                            add.append(new_cs)
                dele.append(cs)

            for cs in dele:
                tmp.remove(cs)
            tmp.extend(add)
        return ret

    def pprint(self):
        print 'CALL STRING:'
        for call in self.stack:
            print call.description
        print

    def set_limitation(self):
        CallString.current_cs = self
        CLimitation.clear()
        for i in range(0, len(self.stack) - 1):
            callee = self.stack[i]
            caller = self.stack[i + 1]
            if callee.is_oc_function:
                cl = CLimitation(caller.ea, 'MSG', target_str=callee.selector, target_ea=self.extra[(caller.ea, callee.ea)])
            else:
                cl = CLimitation(caller.ea, 'C', target_ea=self.extra[(caller.ea, callee.ea)])
            cl.calculate_valid_blocks_to_criterion()
            cl.target_api = callee

    def run(self, analyzer):
        for i in range(0, len(self.stack) - 1):
            callee = self.stack[i]
            caller = self.stack[i + 1]
            if callee.function:
                id = CallSite.add(callee.function, caller.function)
            else:  # external objective-c method
                id = CallSite.add(callee.function, caller.function, criterion=callee.description)
            if id:
                analyzer.analyze_function(start_addr=caller.function, from_cs=True)
            else:
                # 在ctx中执行到callee调用处的路径及调用节点信息已经存在，无需再次执行
                pass

    def should_step_in(self):
        pass




