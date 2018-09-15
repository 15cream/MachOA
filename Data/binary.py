__author__ = 'gjy'

import angr
import archinfo
from Data.class_o import class_o
import os


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

    def read_str_from_cfstring(self, state, addr):
        str = state.memory.load(addr + 0x10, 8, endness=archinfo.Endness.LE).args[0] - 0x100000000
        length = state.memory.load(addr + 0x18, 8, endness=archinfo.Endness.LE).args[0]
        str = self.macho._read(self.macho.binary_stream, str, length)
        return str

    @staticmethod
    def resolve_invoke(state, addr, symbol=None):
        if symbol:
            MachO.pd.task.current_f.insert_invoke(state, addr, symbol=symbol)
        else:
            receiver = MachO.resolve_receiver(state, state.regs.x0.args[0])
            selector = MachO.resolve_selector(state, state.regs.x1.args[0])
            MachO.pd.task.current_f.insert_invoke(state, addr, selector, receiver)
            description = '[' + receiver + ' ' + selector + ']'
            # print hex(addr), "bl _objc_msgSend: {}".format(description)

    @staticmethod
    def resolve_receiver(state, receiver):
        cfstring = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__cfstring')
        cstring = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__cstring')
        data_const = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__const')
        text_const = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__const')
        if receiver in class_o.classes_indexed_by_ref:
            receiver = class_o.classes_indexed_by_ref[receiver].name
        elif receiver in class_o.binary_class_set:
            receiver = class_o.binary_class_set[receiver].name
        elif receiver in range(cfstring.min_addr, cfstring.max_addr):
            receiver = MachO.read_cfstring(state, receiver)
        elif receiver in range(cstring.min_addr, cfstring.max_addr):
            receiver = state.mem[receiver].string.concrete
        elif receiver in range(data_const.min_addr, data_const.max_addr):
            receiver = state.mem[receiver].string.concrete
        elif receiver in range(text_const.min_addr, text_const.max_addr):
            receiver = state.mem[receiver].string.concrete
        elif type(receiver) == str:
            receiver = '_'.join(receiver.split('_')[0:-2])
            # val = MachO.pd.read_str_from_cfstring(state, val)
        # print "reveiver name :".format(receiver.name)
        return str(receiver)

    @staticmethod
    def resolve_arg(state, reg_name):
        reg = state.regs.get(reg_name)
        # reg = state.solver.eval()
        return MachO.resolve_receiver(state, reg.args[0])
        # elif val in MachO.pd.cstring:
        #     val = MachO.pd.cstring[val]


    @staticmethod
    def resolve_selector(state, selector):
        return state.mem[selector].string.concrete

    @staticmethod
    def read_cfstring(state, addr):
        return state.mem[addr+16].deref.string.concrete

    @staticmethod
    def hook_stubs(state):
        __stubs = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__stubs')
        st = state.copy()
        for ptr in range(__stubs.min_addr, __stubs.max_addr, 12):
            st.regs.ip = ptr
            st.step(num_inst=1)
            pass






