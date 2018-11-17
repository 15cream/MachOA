__author__ = 'gjy'

import os

from BinaryPatch.Utils import *
from OCClass import OCClass
from OCFunction import OCFunction

class MachO:

    pd = None

    def __init__(self, binary, task):
        MachO.pd = self
        self.macho = binary
        self.task = task
        self.functions = dict()
        self.stubs = dict()  # stub_code -> symbol_name
        self.segdata = dict()
        self.libs = dict()

    def build(self, state):
        self.build_segdata()
        self.build_classdata(state)
        OCFunction.build_meth_list(self.macho)

    def build_classdata(self, state):
        db = "{}{}.pkl".format(self.task.configs.get('PATH', 'dbs'), self.macho.provides)
        if os.path.exists(db):
            OCClass.unpack(state, db)
            return
        # imported
        classrefs = self.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_classrefs')
        superrefs = self.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_superrefs')
        symbols = self.macho.symbols
        for s in symbols:
            for addr in s.bind_xrefs:
                if addr in range(classrefs.min_addr, classrefs.max_addr) or addr in range(superrefs.min_addr, superrefs.max_addr):
                    OCClass(addr, imported=True, name=s.name.split('$_')[-1]).build(state)
        # binary classes
        for addr in range(classrefs.min_addr, classrefs.max_addr, 8):
            if addr in OCClass.imported_class_set:
                continue
            else:
                OCClass(addr).build(state)
        for addr in range(superrefs.min_addr, superrefs.max_addr, 8):
            if addr in OCClass.imported_class_set:
                continue
            else:
                OCClass(addr).build(state)
        OCClass.dump(db)

    def build_segdata(self):
        self.segdata['cfstring'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__cfstring')
        self.segdata['cstring'] = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__cstring')
        self.segdata['data_const'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__const')
        self.segdata['text_const'] = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__const')
        self.segdata['class_ref'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_classrefs')
        self.segdata['superrefs'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_superrefs')
        self.segdata['classdata'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_data')
        self.segdata['methname'] = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__objc_methname')
        self.segdata['code'] = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text')
        self.segdata['common'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__common')
        self.segdata['bss'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__bss')

    def parse_symbols(self):
        for s in self.macho.symbols:
            print 'SYMBOL: -- {} --'.format(s.name)
            print 'addr: {}'.format(hex(s.addr))
            print 'bind_xrefs: {}'.format(s.bind_xrefs)
            print 'is_import: {}'.format(s.is_import)
            print 'library_name: {}'.format(s.library_name)
            if s.is_import:
                if s.library_name not in self.libs or s not in self.libs[s.library_name]:
                    self.libs[s.library_name] = [s, ]
                else:
                    self.libs[s.library_name].append(s)




