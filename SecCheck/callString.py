# coding=utf-8
from seed import *
import copy


class CallString:

    def __init__(self):
        self.stack = []
        self.seed = None

    def copy(self):
        cs_copy = CallString()
        cs_copy.seed = self.seed
        cs_copy.stack = copy.deepcopy(self.stack)
        return cs_copy

    def copy_and_add(self, call):
        cs_copy = self.copy()
        # 避免循环调用
        for c in cs_copy.stack:
            if c.description == call.description:
                return None
        cs_copy.stack.append(call)
        return cs_copy

    @staticmethod
    def construct_according_to_a_seed(seed):
        ret = []
        tmp = []

        init_cs = CallString()
        init_cs.seed = seed
        init_cs.stack.append(seed)
        tmp.append(init_cs)

        while tmp:
            dele = []
            add = []
            for cs in tmp:
                callee = cs.stack[-1]
                callee.find_calls(gist='ADJ')
                if not callee.calls:
                    ret.append(cs)
                else:
                    for caller in callee.calls:
                        _caller = None
                        if caller in OCFunction.oc_function_set:
                            oc_func = OCFunction.oc_function_set[caller]
                            _caller = cs.copy_and_add(API(receiver=oc_func.receiver, selector=oc_func.selector, ea=caller))
                        elif caller in OCFunction.meth_data:
                            _caller = cs.copy_and_add(API(func=OCFunction.meth_data[caller]['name'], ea=caller))
                        if _caller and _caller not in add:
                            add.append(_caller)
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

    # TODO 要记录调用发生或数据被引用的位置（block），随后再根据CFG限制符号执行的路径，后续可能还需要污点分析技术
