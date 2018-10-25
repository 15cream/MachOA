import idc
import idaapi
import idautils
from Utils import *
from Constants import *


class Object:

    def __init__(self, c, data):
        self._class = c
        self.bin_data = data
        self._classref = None
        self.init_class_data()
        self.suspected_ctx = set()

    def init_class_data(self):
        if self._class in self.bin_data['classrefs']:
            self._classref = self.bin_data['classrefs'][self._class]
        else:
            print 'CANNOT FIND CLASS: ', self._class
            return False

    # self._classref And 'alloc' selector
    def find_alloc(self):
        r = []
        if 'alloc' in SPECS[self._class]:
            alloc_sel = SPECS[self._class]['alloc']
        else:
            alloc_sel = 'alloc'
        alloc_dict = dict()
        for xref in idautils.XrefsTo(self.bin_data['selrefs'][alloc_sel]):
            fi = idaapi.get_func(xref.frm).startEA
            if fi not in alloc_dict:
                alloc_dict[fi] = [xref.frm]
            else:
                alloc_dict[fi].append(xref.frm)
        s1 = set(alloc_dict.keys())
        s2 = set()

        for xref in idautils.XrefsTo(self._classref):
            if idc.SegName(xref.frm) == '__text':
                fi = idaapi.get_func(xref.frm).startEA
                s2.add(fi)
        r = list(s1 & s2)
        self.suspected_ctx.update(r)
        return r

    # When the self._class type ivars were referenced,
    # whether get or set, load or store,
    # the self._class type objects must exist in this context.
    def find_ivar_refs(self):
        r = []
        if self._class in self.bin_data['ivars2']:
            for ivar in self.bin_data['ivars2'][self._class]:
                for xref in idautils.XrefsTo(ivar):
                    if idc.SegName(xref.frm) == '__text':
                        fi = idaapi.get_func(xref.frm).startEA
                        if fi not in r:
                            r.append(fi)
                            self.extra_check('ivar', xref.frm)
        self.suspected_ctx.update(r)
        return r

    # The X0 register of instance methods is always the self._class type object
    def find_instance_methods(self):
        r = []
        if idc.SegName(idc.Qword(self._classref)) == 'UNDEF':
            return r  # IMPORTED CLASS
        class_data = idc.Qword(self._classref)
        class_data_ro = idc.Qword(class_data + 0x20)
        meths = idc.Qword(class_data_ro + 0x20)
        entrysize = idc.Word(meths)
        count = idc.Word(meths)
        for meth in range(meths + 8, meths + 8 + entrysize * count, entrysize):
            name = idc.Name(idc.Qword(meth)).replace('sel_', '')
            type = idc.GetDisasm(idc.Qword(meth + 8))
            imp = idc.Qword(meth + 0x10)
            if imp not in r:
                r.append(imp)
                self.extra_check('imeth', imp)
        self.suspected_ctx.update(r)
        return r

    def extra_check(self, type, ea):
        if find_return_type(idaapi.get_func(ea).startEA) == "@":
            self.check_obj_as_ret(type, ea)
        self.check_obj_as_arg(type, ea)

    def check_obj_as_ret(self, type, ea):
        print 'SHOULD DO RET VALUE CHECK AT {}.'.format(hex(ea))

    def check_obj_as_arg(self, type, ea):
        print "SHOULD DO ARG PROPAGATE CHECK AT {}.".format(hex(ea))

    def find_occurance(self):
        self.find_alloc()
        self.find_instance_methods()
        self.find_ivar_refs()
        return self.suspected_ctx

