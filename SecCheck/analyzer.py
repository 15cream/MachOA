#coding=utf-8
from BinaryPatch.Utils import *
from RuntimePatch.Utils import resolve_context


class Analyzer:

    APIs = []
    ADTs = []
    SINKs = []
    current_cs_limited = None

    containers = {
        'NSMutableDictionary': [
            'addEntriesFromDictionary:'
        ]
    }

    def __init__(self):
        pass

    @staticmethod
    def sensitive_API(msg=None, symbol=None):
        if msg:
            for API in Analyzer.APIs:
                if API.is_oc_function and msg.selector.expr == API.selector:
                    # 这里关于receiver的精准度可以控制
                    if msg.receiver.oc_class and msg.receiver.oc_class.name == API.receiver:
                        return True
            if msg.receiver.oc_class:
                if Analyzer.sensitive_ADT(msg.receiver.oc_class.name):
                    return True
            return False
        elif symbol:
            for API in Analyzer.APIs:
                if not API.is_oc_function:
                    if API.function == symbol:
                        return True
            return False

    @staticmethod
    def sensitive_ADT(type):
        for ADT in Analyzer.ADTs:
            if ADT.type == type:
                return True
        return False

    @staticmethod
    def msg_tainted(msg):
        if msg.selector.args:
            for arg in msg.selector.args:
                expr = arg.expr
                try:
                    m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', expr)
                    if m:
                        if 'Marked' in m.group('data_type'):
                            if msg.receiver.oc_class and msg.receiver.oc_class.name in Analyzer.containers:
                                if msg.selector.expr in Analyzer.containers[msg.receiver.oc_class.name]:
                                    msg.receiver.data.mark()
                            return True
                except TypeError as e:
                    print 'TypeError: ', e
        if 'Marked' in msg.receiver.data.expr:
            return True
        return False
        # 其实曾经使用过对向量添加属性的方式，但发现BVS在copy时不会copy新添加的属性；除非去修改这个方法或者继承后覆写。
        # state.regs.get("x{}".format(i)).ast.__setattr__('tainted', True)
        # state.regs.get("x{}".format(i)).ast.tainted

    @staticmethod
    def allowed_step_in(msg, imp):
        if Analyzer.current_cs_limited:
            current_ctx = resolve_context(msg.invoke_ea)
            stack = Analyzer.current_cs_limited.stack
            index = 0
            while index < len(stack):
                if stack[index].ea == current_ctx:
                    break
                index += 1
            if stack[index - 1].ea == imp:
                return True
        return False

    @staticmethod
    def is_sink(msg):
        pass
