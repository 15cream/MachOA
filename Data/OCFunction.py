# coding=utf-8

from Data.OCProtocol import Protocol
from Data.CONSTANTS import *
from tools.oc_type_parser import parser1


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
        for p in oc_class.prots.keys():
            protocol = Protocol.protocol_indexed_by_name[p]
            meth_types = ['class_meths', 'inst_meths', 'opt_class_meths', 'opt_inst_meths']
            for mt in meth_types:
                if sel in protocol.__dict__[mt]:
                    return parser1(protocol.__dict__[mt][sel])

        functions_match_sel = OCFunction.meth_indexed_by_sel[sel] if sel in OCFunction.meth_indexed_by_sel else None
        rec = oc_class.name
        if rec and functions_match_sel:
            for f in functions_match_sel:
                if rec == f.receiver:  # Think about superclass
                    # check if accessor
                    for ivar in oc_class.ivars.values():
                        ivar.parse_accessors()
                        if f.selector == ivar.getter:
                            return [ivar.type, ]
                    return parser1(f.prototype)

        # Now, you know the receiver's instance_type(maybe 'unknown'), the selector,
        # infer the prototype.
        for (_rec, _sel), _ret in REC_SEL_RET.items():
            if sel == _sel:
                if not _rec:  # None, return the receiver class
                    return ['@"{}"'.format(oc_class.name)]
                else:
                    return ['@"{}"'.format(_ret)]

        return ['unknown']

    @staticmethod
    def ask_for_imp(rec=None, sel=None, send_super=False):
        """
        Find the method implementation to handle a message. How about category?
        :param rec: oc_class object
        :param sel: selector string
        :return:
        """
        if sel and sel.expr in OCFunction.meth_indexed_by_sel:
            if rec:
                if send_super:
                    super_classes = []
                    classes_imp_sel = dict()

                    superclass_addr = rec.superclass_addr
                    while superclass_addr:
                        if superclass_addr not in rec.binary_class_set:
                            break  # TODO Check the reason.
                        super_classes.append(rec.binary_class_set[superclass_addr].name)
                        superclass_addr = rec.binary_class_set[superclass_addr].superclass_addr
                    for f in OCFunction.meth_indexed_by_sel[sel.expr]:
                        classes_imp_sel[f.receiver] = f
                    for c in super_classes:
                        if c in classes_imp_sel:
                            return classes_imp_sel[c].imp
                else:
                    for f in OCFunction.meth_indexed_by_sel[sel.expr]:
                        if rec and f.receiver == rec.name:  # should consider superclass ? category?
                            return f.imp
            else:
                if len(OCFunction.meth_indexed_by_sel[sel.expr]) == 1:
                    return OCFunction.meth_indexed_by_sel[sel.expr][0].imp
        return None











