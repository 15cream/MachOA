from Data.OCClass import *


class TypeInfer:

    def __init__(self):
        pass

    @staticmethod
    def infer_by_sel(sel):
        class_names = []
        if sel in OCClass.classes_indexed_by_selector:
            for oc in OCClass.classes_indexed_by_selector[sel]:
                class_names.append(oc.name)
        return class_names

    @staticmethod
    def type_match(accurate, rec, sel):
        if accurate in rec:
            return True
        if accurate in TypeInfer.infer_by_sel(sel):
            return True
        return False

    @staticmethod
    def run(msg):
        if msg.selector.expr == 'respondsToSelector:':
            TypeInfer.deal_respond_to_sel(msg)

    @staticmethod
    def deal_respond_to_sel(msg):
        print 'T'

