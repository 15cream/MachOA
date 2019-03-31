# coding=utf-8

from Data.OCProtocol import Protocol
from Data.CONSTANTS import *
from tools.oc_type_parser import parser1
import re


class OCFunction:

    meth_list = []
    meth_data = dict()
    function_symbols = dict()
    meth_indexed_by_sel = dict()
    oc_function_set = dict()

    def __init__(self, imp=None, rec=None, sel=None, prot=None, meth_type=None):
        self.imp = imp
        self.receiver = rec
        self.selector = sel
        self.prototype = prot
        self.meth_type = meth_type
        self.expr = "{}[{} {}]".format(self.meth_type, self.receiver, self.selector)
        self.ret_type = prot.split('@0:8')[0] if prot else None
        if self.imp not in OCFunction.oc_function_set:
            OCFunction.oc_function_set[imp] = self

    @staticmethod
    def build_meth_list(binary):

        OCFunction.meth_list = binary.lc_function_starts
        for imp in OCFunction.meth_list:
            if imp in OCFunction.oc_function_set:
                f = OCFunction.oc_function_set[imp]
                _selector = f.selector
                _class = f.receiver
                if _selector not in OCFunction.meth_indexed_by_sel:
                    OCFunction.meth_indexed_by_sel[_selector] = [f]
                else:
                    OCFunction.meth_indexed_by_sel[_selector].append(f)
                _name = "{} {}".format(_class, _selector)
            else:
                _name = 'sub_' + str(hex(imp))
                _class = None
            if imp not in OCFunction.meth_data:
                OCFunction.meth_data[imp] = {'name': _name, 'class': _class}

            if _name not in OCFunction.function_symbols:
                OCFunction.function_symbols[_name] = imp

    @staticmethod
    def find_detailed_prototype(sel, oc_class):
        if not oc_class:
            return ['unknown']

        if Frameworks.query(oc_class.name, sel):
            return Frameworks.query(oc_class.name, sel)

        # 预定义的规则
        for (_rec, _sel), _ret in REC_SEL_RET.items():
            if sel == _sel:
                if not _rec:  # None, return the receiver class
                    return ['@"{}"'.format(oc_class.name)]
                else:
                    return ['@"{}"'.format(_ret)]

        # 检查该类实现的协议，看当前方法是否为协议中定义的方法，如是，则表明存在方法原型
        for p in oc_class.prots.keys():
            protocol = Protocol.protocol_indexed_by_name[p]
            meth_types = ['class_meths', 'inst_meths', 'opt_class_meths', 'opt_inst_meths']
            for mt in meth_types:
                if sel in protocol.__dict__[mt]:
                    return parser1(protocol.__dict__[mt][sel])

        # 根据selector查找可能的receiver，然后与当前方法的receiver做对比，如匹配则能找到方法原型，虽然不完整；
        # 注意一个福利，如果得知当前方法是getter的话，那么可以得知获得的属性类型，即返回值。
        functions_match_sel = OCFunction.meth_indexed_by_sel[sel] if sel in OCFunction.meth_indexed_by_sel else None
        rec = oc_class.name
        if rec and functions_match_sel:
            for f in functions_match_sel:
                if rec == f.receiver:  # Think about the superclass
                    # check if accessor
                    for ivar in oc_class.ivars.values():
                        ivar.parse_accessors()
                        if f.selector == ivar.getter:
                            return [ivar.type, ]
                    return parser1(f.prototype)

        return ['unknown']

    @staticmethod
    def ask_for_imp_at_runtime(rec=None, sel=None, send_super=False):
        """
        Find the method implementation to handle a message. How about category?
        :param rec: Receiver object
        :param sel: SEL object
        :return:
        """
        if not rec.valid:
            return None

        if sel.expr in performSelectors:
            selector = sel.args[0].expr
        else:
            selector = sel.expr

        if selector not in OCFunction.meth_indexed_by_sel:
            return None

        classes_imp_sel = {}
        for f in OCFunction.meth_indexed_by_sel[selector]:
            classes_imp_sel[f.receiver] = f

        if rec.oc_class:
            rec = rec.oc_class
            if send_super:
                superclass_addr = rec.superclass_addr
                while superclass_addr:
                    if superclass_addr not in rec.binary_class_set:
                        break  # TODO Check the reason.
                    _class = rec.binary_class_set[superclass_addr]
                    if _class.name in classes_imp_sel:
                        return classes_imp_sel[_class.name].imp
                    superclass_addr = _class.superclass_addr
            else:
                for f in OCFunction.meth_indexed_by_sel[selector]:
                    if rec and f.receiver == rec.name:  # TODO  should consider superclass ? category?
                        return f.imp
            return None
        else:
            # 这里是不合理的其实，当receiver的类型未知时，selector也可能是导入的类的selector。
            # if len(OCFunction.meth_indexed_by_sel[selector]) == 1:
            #     return OCFunction.meth_indexed_by_sel[selector][0].imp
            return [rec.dpr, selector]

    @staticmethod
    def find_protocol_method(proto, sel):
        return []










