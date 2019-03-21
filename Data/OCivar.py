__author__ = 'gjy'
import pickle
from OCFunction import OCFunction
from Data.CONSTANTS import *


class IVar:

    ivars = dict()
    xrefs = dict()
    ivars_accessed_during_analysis = set()

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
        self.records = []

    @staticmethod
    def init(xref_pkl):
        f = open(xref_pkl)
        IVar.xrefs = pickle.load(f)
        f.close()

    def add_to_ivars(self):
        if self.ptr not in IVar.ivars:
            IVar.ivars[self.ptr] = self

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

    def add_record(self, record):
        self.records.append(record)
        if self.ptr not in IVar.ivars_accessed_during_analysis:
            IVar.ivars_accessed_during_analysis.add(self.ptr)

    @staticmethod
    # deprecated for the moment
    def _parse_accessor():
        """
        For each ivar, check the function used it, and predicate this function to be accessor or not.
        :return:
        """
        for ivar_ptr, ivar in IVar.ivars.items():
            # xrefs_to_ivar = IVar.xrefs['ivar'][ivar_ptr]
            xrefs_to_ivar = Xrefs.ask_for_xrefs(ivar_ptr, 'ivar')
            setter = 'set{}:'.format(ivar.name.strip('_')).upper()
            getter = ivar.name.strip('_').upper()

            for xref, fi in xrefs_to_ivar.items():
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


class AccessedRecord:

    def __init__(self, ea, type, direct=True, ctx=None, value=None):
        """

        :param ea: exactly address where the accessed happened.
        :param type: get or set
        :param ctx:
        :param value:
        :param direct: direct or through accessor methods
        """
        self.ea = ea
        self.ctx = ctx
        self.type = type
        self.value = value
        self.direct_ref = direct
        self.path = None  # actually, if path-sensitive