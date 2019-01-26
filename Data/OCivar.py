__author__ = 'gjy'
import pickle
from OCFunction import OCFunction
from Data.CONSTANTS import *


class IVar:

    ivars = dict()
    xrefs = dict()

    def __init__(self, ptr, name=None, _class=None, type=None):
        self.ptr = ptr
        self.name = name
        self._class = _class
        self.type = type
        self.property = None
        self.getter = None
        self.setter = None
        self.dealloc = []
        self.init = []
        self.direct_ref = {}  # function: [ea1, ea2, ...]

    @staticmethod
    def init(xref_pkl):
        f = open(xref_pkl)
        IVar.xrefs = pickle.load(f)
        f.close()

    def add_to_ivars(self):
        if self.ptr not in IVar.ivars:
            IVar.ivars[self.ptr] = self

    @staticmethod
    # deprecated for the moment
    def _parse_accessor():
        """
        For each ivar, check the function used it, and predicate this function to be accessor or not.
        :return:
        """
        for ivar_ptr, ivar in IVar.ivars.items():
            setter = 'set{}:'.format(ivar.name.strip('_')).upper()
            getter = ivar.name.strip('_').upper()
            for xref, fi in IVar.xrefs['ivar'][ivar_ptr].items():
                if fi in OCFunction.oc_function_set:
                    f = OCFunction.oc_function_set[fi]
                    if f.selector.upper() == setter:
                        ivar.setter = f
                    elif f.selector.upper() == getter:
                        ivar.getter = f
                    elif f.selector.lower() in ['dealloc', '.cxx_destruct']:
                        ivar.dealloc.append(f)
                    elif 'init' in f.selector.lower():
                        ivar.init.append(f)
                    else:
                        if fi in ivar.direct_ref:
                            ivar.direct_ref[fi].append(xref)
                        else:
                            ivar.direct_ref[fi] = [xref]

    def parse_accessors(self):
        if self.property:
            if self.setter:
                pass
            else:
                self.setter = "set{}:".format(self.property[0].upper() + self.property[1:])
            if self.getter:
                pass
            else:
                self.getter = "{}:".format(self.property)


