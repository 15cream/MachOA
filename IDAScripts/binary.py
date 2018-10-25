import idautils
import idaapi
import idc
import pickle
import os
import re


class Binary:

    def __init__(self):
        self.parser = {
            '__objc_classrefs': self.parse_class,
            '__objc_superrefs': self.parse_class,
            '__objc_selrefs': self.parse_selector,
            '__objc_ivar': self.parse_ivar
        }
        self._classrefs = dict()
        self._selrefs = dict()
        self._ivars = dict()  # ivar_ea: type
        self._ivars_2 = dict()  # type:  ivar_ea list
        self._allocs = []
        self.callG = dict()

    def parse_class(self, ea):
        classname = idc.Name(ea).replace('classRef_', '')
        self._classrefs[classname] = ea

    def parse_selector(self, ea):
        m = re.search('[^"]+"(?P<sel>.+)"', idc.GetDisasm(ea))
        if m:
            self._selrefs[m.group('sel')] = ea

    def parse_ivar(self, ea):
        cmt = idc.GetCommentEx(ea, True)
        if cmt:
            type = cmt.split()[0]
            self._ivars[ea] = type
            if type in self._ivars_2:
                self._ivars_2[type].append(ea)
            else:
                self._ivars_2[type] = [ea, ]
        else:
            print 'CANNOT GET CMT OF IVAR: '.format(hex(ea))

    def run(self):
        for seg in idautils.Segments():
            segName = idc.SegName(seg)
            if segName in ['__objc_classrefs', '__objc_superrefs', '__objc_selrefs']:  # step: 8
                for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 8):
                    self.parser[segName](ea)
            elif segName in ['__objc_ivar']:  # step: 4
                for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 4):
                    self.parser[segName](ea)
        self.parse_alloc()

    def get_data(self):
        return {
            'classrefs': self._classrefs,
            'selrefs': self._selrefs,
            'ivars': self._ivars,
            'ivars2': self._ivars_2,
            'allocs': self._allocs,
        }

    def parse_alloc(self):
        r = []
        for xref in idautils.XrefsTo(self._selrefs['alloc']):
            fi = idaapi.get_func(xref.frm).startEA
            if fi not in r:
                r.append(fi)
        self._allocs = r

    # def dump_data(self):
    #     f = open('/home/gjy/Desktop/MachOA/IDAScripts/dbs/WeiBo.pkl', 'wb')
    #     pickle.dump(self.get_data(), f)
    #     f.close()
    #
    # def restore_from_db(self):
    #     if os.path.exists('/home/gjy/Desktop/MachOA/IDAScripts/dbs/WeiBo.pkl'):
    #         f = open('/home/gjy/Desktop/MachOA/IDAScripts/dbs/WeiBo.pkl')
    #         data = pickle.load(f)
    #         try:
    #             self._classrefs = data['classrefs']
    #             self._selrefs = data['selrefs']
    #         except KeyError as e:
    #             print e
    #         f.close()
    #     else:
    #         return False
