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
                _name = f.selector
                _class = f.receiver
                if _name not in OCFunction.meth_indexed_by_sel:
                    OCFunction.meth_indexed_by_sel[_name] = [f]
                else:
                    OCFunction.meth_indexed_by_sel[_name].append(f)
            else:
                _name = 'sub_' + str(hex(imp))
                _class = None
            if imp not in OCFunction.meth_data:
                OCFunction.meth_data[imp] = {'name': _name, 'class': _class}

            if _name not in OCFunction.function_symbols:
                OCFunction.function_symbols[_name] = imp

    @staticmethod
    def find_detailed_prototype(sel, oc_class):
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







