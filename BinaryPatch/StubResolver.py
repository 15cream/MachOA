# _*_coding:utf-8_*_

import angr


# ADRP            X16, #_objc_retain_ptr@PAGE
# LDR             X16, [X16,#_objc_retain_ptr@PAGEOFF]
# BR              X16     ; __imp__objc_retain
# find the corresponding relation between stubs code and symbol (not the symbol imp)

class StubResolver:

    resolver = None

    def __init__(self, state, MachOFile):
        self.state = state
        self.mf = MachOFile
        self.bin = MachOFile.macho
        StubResolver.resolver = self

    @staticmethod
    def run():
        this = StubResolver.resolver
        state = this.state
        stubs = this.bin.get_segment_by_name('__TEXT').get_section_by_name('__stubs')
        bp = state.inspect.b('mem_read', when=angr.BP_BEFORE, action=StubResolver.constructor)
        for stub in range(stubs.min_addr, stubs.max_addr, 12):
            state.regs.ip = stub
            state.step()
        state.inspect.remove_breakpoint('mem_read', bp=bp)

    @staticmethod
    def constructor(state):
        this = StubResolver.resolver
        stub_code_addr = state.addr - 4
        if stub_code_addr not in this.mf.stubs:
           this.mf.stubs[stub_code_addr] = this.bin.get_symbol_by_address_fuzzy(state.solver.eval(state.inspect.mem_read_address))




