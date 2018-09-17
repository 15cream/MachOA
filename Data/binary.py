__author__ = 'gjy'

import angr
import archinfo
from Data.class_o import class_o
import os
import function
from Data.CONSTANTS import *


class MachO:

    pd = None

    def __init__(self, binary, loader, project, task):
        self.macho = binary
        self.loader = loader
        self.project = project
        self.task = task
        MachO.pd = self
        self.functions = dict()
        angr.types.define_struct('struct methlist{int entrysize; int count;}')
        angr.types.define_struct('struct meth{char* name; long type; long imp;}')
        self.stubs = dict()  # stub_code -> symbol_name
        self.segdata = dict()
        self.build_segdata()

    def build_classdata(self, state):
        db = "{}{}.pkl".format(self.task.configs.get('PATH', 'dbs'), self.macho.provides)
        if os.path.exists(db):
            class_o.unpack(state, db)
            return
        # imported
        classrefs = self.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_classrefs')
        symbols = self.macho.symbols
        for s in symbols:
            for addr in s.bind_xrefs:
                if addr in range(classrefs.min_addr, classrefs.max_addr):
                    class_o(addr, imported=True, name=s.name).build(state)
        # binary classes
        for addr in range(classrefs.min_addr, classrefs.max_addr, 8):
            if addr in class_o.imported_class_set:
                continue
            else:
                class_o(addr).build(state)
        class_o.dump(db)


    def build_segdata(self):
        self.segdata['cfstring'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__cfstring')
        self.segdata['cstring'] = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__cstring')
        self.segdata['data_const'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__const')
        self.segdata['text_const'] = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__const')
        self.segdata['classref'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_classrefs')
        self.segdata['classdata'] = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_data')
        self.segdata['methname'] = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__objc_methname')

    @staticmethod
    def resolve_invoke(state, type=None):

        src_state = state.history.parent.parent
        addr = src_state.addr + src_state.recent_instruction_count * 4
        symbol = MachO.pd.stubs[state.history.parent.addr]

        if type == LAZY_BIND_F:
            MachO.pd.task.current_f.insert_invoke(state, addr, symbol=symbol)
        elif type == MSGSEND:
            receiver = MachO.pd.resolve_reg(state, state.regs.x0)
            selector = MachO.pd.resolve_reg(state, state.regs.x1)
            if 'instance' in receiver:
                receiver = receiver.split('_')[0]
                meth_type = '-'
            else:
                meth_type = '+'
            imp = function.Function.retrieve_f("{}[{} {}]".format(meth_type, receiver, selector), ret=0b00100)
            if imp:
                MachO.pd.task.current_f.insert_invoke(state, addr, selector, receiver, type=INTERINVOKE)
                return imp.pop()
            MachO.pd.task.current_f.insert_invoke(state, addr, selector, receiver)

        return "RetFrom_" + hex(addr)

    def resolve_reg(self, state, reg):
        op = reg.op
        args = reg.args
        if op == 'BVV':
            repr = self.resolve_addr(state, args[0])
        elif op == 'BVS':
            repr = '_'.join(args[0].split('_')[0:-2])
        else:
            repr = str(reg)
        return repr

    def resolve_addr(self, state, addr):
        datatype = None
        for segname, seg in self.segdata.items():
            if addr in range(seg.min_addr, seg.max_addr):
                datatype = segname
                break
        if datatype == 'classref':
            return class_o.classes_indexed_by_ref[addr].name
        elif datatype == 'classdata':
            return class_o.binary_class_set[addr].name
        elif datatype == 'cfstring':
            return MachO.read_cfstring(state, addr)
        elif datatype in ['cstring', 'data_const', 'text_const', 'methname']:
            return state.mem[addr].string.concrete
        else:
            return str(addr)

    @staticmethod
    def read_cfstring(state, addr):
        return state.mem[addr+16].deref.string.concrete

    def read_str_from_cfstring(self, state, addr):
        str = state.memory.load(addr + 0x10, 8, endness=archinfo.Endness.LE).args[0] - 0x100000000
        length = state.memory.load(addr + 0x18, 8, endness=archinfo.Endness.LE).args[0]
        str = self.macho._read(self.macho.binary_stream, str, length)
        return str

    # @staticmethod
    # def hook_stubs(state):
    #     __stubs = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__stubs')
    #     st = state.copy()
    #     for ptr in range(__stubs.min_addr, __stubs.max_addr, 12):
    #         st.regs.ip = ptr
    #         st.step(num_inst=1)






