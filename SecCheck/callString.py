# coding=utf-8
from seed import *
import copy


class CallString:

    def __init__(self):
        self.stack = []
        self.seed = None
        self.extra = dict()

    def copy(self):
        cs_copy = CallString()
        cs_copy.seed = self.seed
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

    def add_constraints_for_meth_to_reach_callsite(self, caller_ctx, callee, info):
        self.extra[(caller_ctx, callee)] = info

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
                callers = callee.find_calls_for_cs()
                if not callers:
                    ret.append(cs)  # event handler,　是否要查找event handler对应的event occurrence?
                else:
                    # 注意，对一个给定的callee，我们想要查找它的caller——无法准确查找到call site。
                    # 只能告诉你，在caller_ctx这个方法体内，借助caller_info可能定位到caller(call site)的位置。
                    # 从callString中我们可以看到caller_ctx这个方法调用了callee，但是在哪里调用呢？具体执行了才知道。
                    for caller_ctx, caller_info in callers.items():  # caller_info是在caller_ctx中到达call site的约束信息
                        new_cs = None
                        if caller_ctx in OCFunction.oc_function_set:
                            oc_func = OCFunction.oc_function_set[caller_ctx]
                            meth = API(receiver=oc_func.receiver, selector=oc_func.selector, ea=caller_ctx)
                        elif caller_ctx in OCFunction.meth_data:
                            # 当然如果是subroutine那么可以定位
                            meth = API(func=OCFunction.meth_data[caller_ctx]['name'], ea=caller_ctx)

                        new_cs = cs.copy_and_add(meth)
                        if new_cs and new_cs not in add:
                            new_cs.add_constraints_for_meth_to_reach_callsite(meth.ea, callee.ea, caller_info)
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

    # TODO 要记录调用发生或数据被引用的位置（block），随后再根据CFG限制符号执行的路径，后续可能还需要污点分析技术
