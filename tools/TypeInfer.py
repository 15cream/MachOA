# coding=utf-8
from Data.OCClass import *
from tools.oc_type_parser import type_to_str


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
    def type_match(accurate, node, sel, trace):
        """
        给定一个准确的类型，以及调用的receiver（数据），判断二者类型是否匹配；selector主要用于辅助类型推断。
        matched_node是[accurate sel]，被匹配的节点是[rec sel].
        :param accurate:
        :param rec:
        :param sel:
        :return:
        """
        if accurate == node['rec']:
            return True
        if 'rec_dpr' in node and eval(node['rec_dpr']):
            print 'UPDATE REC'
            dp_ea = int(eval(node['rec_dpr']).keys()[0].strip('L'), 16)
            if dp_ea in trace.ea_node:
                dp_node = trace.ea_node[dp_ea]
                if accurate in dp_node['rec']:
                    return True
        elif 'rec_type' in node:
            rec = type_to_str(node['rec_type'])
            if accurate == rec:
                return True
            if accurate in OCClass.classes_indexed_by_name:
                accurate = OCClass.classes_indexed_by_name[accurate][0]
                classes_imp_sel = {}
                for f in OCFunction.meth_indexed_by_sel[sel]:
                    classes_imp_sel[f.receiver] = f
                if rec in OCClass.classes_indexed_by_name:
                    # 当receiver是已确定的准确类型时
                    rec = OCClass.classes_indexed_by_name[rec][0]
                    # 当accurate是receiver的子类，receiver有实现sel时(因为运行时receiver可以是accurate类型)
                    if rec.name in OCClass.find_superclass_chain(accurate.name) and rec.name in classes_imp_sel:
                        return True
                    # 当accurate是receiver的父类，accurate实现有sel，receiver可以通过msgSendSuper调用[accurate sel]；
                    if accurate.name in OCClass.find_superclass_chain(rec.name) and accurate.name in classes_imp_sel:
                        return True
        return False

    @staticmethod
    def run(msg):
        if msg.selector.expr == 'respondsToSelector:':
            TypeInfer.deal_respond_to_sel(msg)

    @staticmethod
    def deal_respond_to_sel(msg):
        print 'T'

