from Constants import *
from context import CTX, PT
import idc
import idautils
import idaapi

class Object:

    def __init__(self, c, data):
        self.class_name = c
        self.bin_data = data
        self.class_ref = None
        self.occurrences = dict()

        if self.class_name in self.bin_data['classrefs']:
            self.class_ref = self.bin_data['classrefs'][self.class_name]
        else:
            print 'CANNOT FIND CLASS: ', self.class_name
            return None

    def add_occurrences(self, ea):
        f = idaapi.get_func(ea)
        if f:
            fi = f.startEA
            if fi in self.occurrences:
                self.occurrences[fi].append(ea)
            else:
                self.occurrences[fi] = [ea, ]

    def update_occurrences(self, olist):
        self.occurrences.extend(olist)

    def get_occurrences(self):
        return self.occurrences

    def find_occurrences(self):
        self.as_x0()
        self.as_new()
        self.as_ivar()
        # self.as_predefined_get()

    # we have already known this method would return the object.
    def as_predefined_get(self):
        r = []
        if self.class_name in SPECS:
            sel = SPECS[self.class_name]

            for xref in idautils.XrefsTo(self.class_ref):
                if idc.SegName(xref.frm) == '__text':
                    if idc.GetMnem(xref.frm) == 'ADRP':
                        pass
                    elif 'LDR' in idc.GetMnem(xref.frm):
                        ctx = CTX(xref.frm, PT(idc.GetOpnd(xref.frm, 0), xref.frm))
                        if ctx.find_call(sel=sel):
                            r.append(ctx)
        return r

    # self.class_ref And 'alloc' selector
    def as_new(self):
        for xref in idautils.XrefsTo(self.class_ref):
            if idc.SegName(xref.frm) == '__text':
                if idc.GetMnem(xref.frm) == 'ADRP':
                    pass
                elif 'LDR' in idc.GetMnem(xref.frm):
                    # ctx = CTX(xref.frm, PT(idc.GetOpnd(xref.frm, 0), xref.frm))
                    # if ctx.find_call(rec='x8', sel='alloc'):
                    self.add_occurrences(xref.frm)

    # When the self.class_name type ivars were referenced,
    # whether get or set, load or store,
    # the object must exist in this context.
    def as_ivar(self):
        if self.class_name in self.bin_data['ivars2']:
            for ivar in self.bin_data['ivars2'][self.class_name]:
                for xref in idautils.XrefsTo(ivar):
                    if idc.SegName(xref.frm) == '__text':
                        if idc.GetMnem(xref.frm) == 'ADRP':
                            pass
                        elif 'LDR' in idc.GetMnem(xref.frm):
                            # PT(idc.GetOpnd(xref.frm, 0), xref.frm)
                            # ctx = CTX(xref.frm, PT(idc.GetOpnd(xref.frm, 0), xref.frm))
                            self.add_occurrences(xref.frm)

    # The X0 register of instance methods is always the self.class_name type object
    def as_x0(self):
        if idc.SegName(idc.Qword(self.class_ref)) == 'UNDEF':
            return  # IMPORTED CLASS
        class_data = idc.Qword(self.class_ref)
        class_data_ro = idc.Qword(class_data + 0x20)
        meths = idc.Qword(class_data_ro + 0x20)
        entrysize = idc.Word(meths)
        count = idc.Word(meths)
        for meth in range(meths + 8, meths + 8 + entrysize * count, entrysize):
            name = idc.Name(idc.Qword(meth)).replace('sel_', '')
            type = idc.GetDisasm(idc.Qword(meth + 8))
            imp = idc.Qword(meth + 0x10)
            # ctx = CTX(imp, PT('X0', imp))
            # r.append(ctx)
            self.add_occurrences(imp)
