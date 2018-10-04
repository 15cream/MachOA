__author__ = 'gjy'

import angr
import archinfo
from Data.class_o import class_o
import os
import function
from Data.CONSTANTS import *
import claripy
from CONSTANTS import *

class MachO:

    pd = None

    def __init__(self, binary, loader, project, task):
        MachO.pd = self
        self.macho = binary
        self.loader = loader
        self.project = project
        self.task = task
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
        superrefs = self.macho.get_segment_by_name('__DATA').get_section_by_name('__objc_superrefs')
        symbols = self.macho.symbols
        for s in symbols:
            for addr in s.bind_xrefs:
                if addr in range(classrefs.min_addr, classrefs.max_addr) or addr in range(superrefs.min_addr, superrefs.max_addr):
                    class_o(addr, imported=True, name=s.name.split('$_')[-1]).build(state)
        # binary classes
        for addr in range(classrefs.min_addr, classrefs.max_addr, 8):
            if addr in class_o.imported_class_set:
                continue
            else:
                class_o(addr).build(state)
        for addr in range(superrefs.min_addr, superrefs.max_addr, 8):
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
            # MachO.pd.task.current_f.insert_invoke(state, addr, symbol=symbol)
            MachO.pd.task.cg.insert_invoke(addr, symbol, state, args=MachO.resolve_args(state, symbol=symbol))
            if symbol.name in dispatch:
                base = state.regs.x1
                for i in range(1, 6):
                    ea = state.mem[base + 8 * i].long.concrete
                    if ea in MachO.pd.macho.lc_function_starts:
                        return ea
            return "RetFrom_" + hex(addr)
        elif type == MSGSEND:
            receiver = MachO.pd.resolve_reg(state, state.regs.x0)
            selector = MachO.pd.resolve_reg(state, state.regs.x1)
            if 'instance' in receiver:
                receiver = receiver.split('_')[0]
                meth_type = '-'
            elif '@' in receiver:
                receiver = receiver.split('@')[-1].strip('"')
                meth_type = '-'
            else:
                meth_type = '+'
            description = "{}[{} {}]".format(meth_type, receiver, selector)
            imp = function.Function.retrieve_f(description, ret=0b00100)
            args = MachO.resolve_args(state, selector=selector)

            if imp:
                MachO.pd.task.cg.insert_invoke(addr, description, state,
                                               args=args, receiver=receiver, selector=selector)

                # # MachO.pd.task.current_f.insert_invoke(state, addr, selector, receiver)
                return imp.pop()
                # return addr
            else:
                MachO.pd.task.cg.insert_invoke(addr, description, state,
                                       args=args, receiver=receiver, selector=selector)

                return "RetFrom_" + hex(addr)

    @staticmethod
    def resolve_args(state, selector=None, symbol=None):
        args = []
        if selector:
            args.append(MachO.pd.resolve_reg(state, state.regs.get('x0')))
            argc = selector.count(':')
            for c in range(1, argc + 2):
                reg_name = 'x{}'.format(c)
                reg_val = MachO.pd.resolve_reg(state, state.regs.get(reg_name))
                args.append(reg_val)
            if selector == 'stringWithFormat:':
                formatString = args[2]
                fs_args = formatString.count("@")
                for c in range(3, fs_args + 3):
                    reg_name = 'x{}'.format(c)
                    reg_val = MachO.pd.resolve_reg(state, state.regs.get(reg_name))
                    args.append(reg_val)
        elif symbol:
            args.append(MachO.pd.resolve_reg(state, state.regs.get('x0')))
            args.append(MachO.pd.resolve_reg(state, state.regs.get('x1')))
        return args

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

    def resolve_var(self, state, classname=None, offset=None):
        c = class_o.classes_indexed_by_name[classname]
        if c.imported:
            pass
        else:
            class_data = state.memory.load(c.class_addr + 32, 8, endness=archinfo.Endness.LE)
            ivars = state.memory.load(class_data + 0x30, 8, endness=archinfo.Endness.LE)
            ivar = ivars + (offset / 8 - 1) * 0x20 + 8
            name = state.mem[state.mem[ivar+8].long.concrete].string.concrete
            type = state.mem[state.mem[ivar+16].long.concrete].string.concrete
        return claripy.BVS(classname + name + type, 64).reversed

    @staticmethod
    def resolve_context(ea):
        # find which function this ea resides in
        for f in sorted(MachO.pd.macho.lc_function_starts, reverse=True):
            if ea >= f:
                break
        return f






