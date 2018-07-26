__author__ = 'gjy'

import angr
import archinfo
from Data.class_o import class_o


class MachO:

    pd = None

    def __init__(self, binary, loader, project, analyzer):
        self.macho = binary
        self.loader = loader
        self.project = project
        self.analyzer = analyzer
        self.functions = dict()
        angr.types.define_struct('struct methlist{int entrysize; int count;}')
        angr.types.define_struct('struct meth{char* name; long type; long imp;}')
        self.stubs = dict()  # stub_code -> symbol_name

    def build_classdata(self, state, packed=None):
        if packed:
            class_o.unpack()
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
        class_o.dump()

    def read_str_from_cfstring(self, state, addr):
        str = state.memory.load(addr + 0x10, 8, endness=archinfo.Endness.LE).args[0] - 0x100000000
        length = state.memory.load(addr + 0x18, 8, endness=archinfo.Endness.LE).args[0]
        str = self.macho._read(self.macho.binary_stream, str, length)
        return str

    @staticmethod
    def resolve_invoke(state, addr):
        receiver = MachO.resolve_receiver(state, state.regs.x0.args[0])
        selector = MachO.resolve_selector(state, state.regs.x1.args[0])
        MachO.pd.analyzer.current_f.insert_invoke(state, addr, selector, receiver)
        description = '[' + receiver + ' ' + selector + ']'
        # print hex(addr), "bl _objc_msgSend: {}".format(description)
        return description

    @staticmethod
    def resolve_receiver(state, receiver):
        cfstring = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__cfstring')
        cstring = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__cstring')
        if receiver in class_o.classes_indexed_by_ref:
            receiver = class_o.classes_indexed_by_ref[receiver].name
        elif receiver in class_o.binary_class_set:
            receiver = class_o.binary_class_set[receiver].name
        elif receiver in range(cfstring.min_addr, cfstring.max_addr):
            receiver = MachO.read_cfstring(state, receiver)
        elif receiver in range(cstring.min_addr, cfstring.max_addr):
            receiver = state.mem[receiver].string.concrete
        # print "reveiver name :".format(receiver.name)
        return str(receiver)

    @staticmethod
    def resolve_arg(state, val):
        cfstring = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__cfstring')
        if val in class_o.classes_indexed_by_ref:
            val = class_o.classes_indexed_by_ref[val].name
        elif val in MachO.pd.cstring:
            val = MachO.pd.cstring[val]
        elif val in range(cfstring.min_addr, cfstring.max_addr):
            val = MachO.pd.read_str_from_cfstring(state, val)
        return str(val)

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






