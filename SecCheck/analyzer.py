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
