__author__ = 'gjy'

import os
import pickle
from types import *

from BinaryPatch.Utils import *
from OCClass import OCClass
from OCivar import IVar
from OCFunction import OCFunction
from OCProtocol import Protocol


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

        db = "{}{}.pkl".format(self.task.configs.get('PATH', 'dbs'), self.macho.provides)
        if os.path.exists(db):
            MachO.unpack(state, db)
        else:
            self.build_classdata(state)
            Protocol.analyze_protolist(self.macho, state)
            MachO.dump(db)
        OCFunction.build_meth_list(self.macho)
        # IVar.parse_accessor()

    def build_classdata(self, state):

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

    def build_segdata(self):
        self.segdata['cfstring'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__cfstring')
        self.segdata['cstring'] = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__cstring')
        self.segdata['data_const'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__const')
        self.segdata['objc_const'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_const')
        self.segdata['text_const'] = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__const')
        self.segdata['class_ref'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_classrefs')
        self.segdata['superrefs'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_superrefs')
        self.segdata['classdata'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_data')
        self.segdata['methname'] = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__objc_methname')
        self.segdata['code'] = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text')
        self.segdata['common'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__common')
        self.segdata['bss'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__bss')

    def query_segment(self, ea):
        for seg_name, seg in self.segdata.items():
            if ea in range(seg.min_addr, seg.max_addr):
                return seg_name
        return None

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

    @staticmethod
    def dump(db):
        output = open(db, 'wb')
        pickle.dump([OCClass.class_set, Protocol.protocol_indexed_by_data_EA, OCFunction.oc_function_set], output)
        output.close()

    @staticmethod
    def unpack_deprecated(state, db):
        input = open(db, 'rb')
        [class_set, protocol_set, func_set] = pickle.load(input)
        for cd in class_set:
            if cd.imported:
                OCClass.imported_class_set.append(cd)
                bv = state.solver.BVV(cd.classref_addr, 64).reversed
                state.memory.store(cd.classref_addr, bv)
            else:
                OCClass.binary_class_set[cd.class_addr] = cd

            OCClass.classes_indexed_by_ref[cd.classref_addr] = cd
            OCClass.classes_indexed_by_name[cd.name] = cd
            meths = dict(cd.instance_meths.items() + cd.class_meths.items())
            for meth in meths:
                meth_name = meths[meth]
                OCClass.classes_indexed_by_meth[meth] = [meth_name, cd]
                selector = meth_name.split(' ')[-1].strip(']')
                if selector in OCClass.classes_indexed_by_selector:
                    OCClass.classes_indexed_by_selector[selector].append(cd)
                else:
                    OCClass.classes_indexed_by_selector[selector] = [cd, ]
            if cd.ivars:
                for ivar in cd.ivars:
                    ivar.add_to_ivars()

        Protocol.protocol_indexed_by_data_EA = protocol_set
        for ea, p in protocol_set.items():
            Protocol.protocol_indexed_by_name[p.name] = p

        OCFunction.oc_function_set = func_set

        input.close()

    @staticmethod
    def unpack(state, db):
        input = open(db, 'rb')
        [class_set, protocol_set, func_set] = pickle.load(input)
        for c in class_set:
            cd = OCClass(c['classref_addr'])
            if type(c['class_addr']) is not NoneType:
                cd.class_addr = state.solver.eval(c['class_addr'])
            else:
                cd.class_addr = None
            if type(c['meta_class_addr']) is not NoneType:
                cd.meta_class_addr = state.solver.eval(c['meta_class_addr'])
            else:
                cd.meta_class_addr = None
            cd.name = c['name']
            cd.imported = c['imported']
            cd.class_meths = c['class_meths']
            cd.instance_meths = c['instance_meths']
            cd.prots = c['prots']
            cd.superclass_addr = c['superclass_addr']
            if c['ivars']:
                cd.ivars = c['ivars']
            else:
                cd.ivars = dict()
            if cd.imported:
                OCClass.imported_class_set.append(cd)
                bv = state.solver.BVV(cd.classref_addr, 64).reversed
                state.memory.store(cd.classref_addr, bv)
            else:
                OCClass.binary_class_set[cd.class_addr] = cd
            OCClass.classes_indexed_by_ref[cd.classref_addr] = cd
            OCClass.classes_indexed_by_name[cd.name] = cd
            meths = dict(cd.instance_meths.items() + cd.class_meths.items())
            for meth in meths:
                meth_name = meths[meth]
                OCClass.classes_indexed_by_meth[meth] = [meth_name, cd]
                selector = meth_name.split(' ')[-1].strip(']')
                if selector in OCClass.classes_indexed_by_selector:
                    OCClass.classes_indexed_by_selector[selector].append(cd)
                else:
                    OCClass.classes_indexed_by_selector[selector] = [cd, ]
            for ivar in cd.ivars.values():
                ivar.add_to_ivars()

        Protocol.protocol_indexed_by_data_EA = protocol_set
        for ea, p in protocol_set.items():
            Protocol.protocol_indexed_by_name[p.name] = p

        OCFunction.oc_function_set = func_set

        input.close()






