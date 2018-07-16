# _*_coding:utf-8_*_
from binary import MachO
from tools.hooks import *


#  通常stubs会跳到该 symbol 在__la_symbol_ptr中存放的imp地址，存在其他情况吗？
#  __la_symbol_ptr中的imp地址，部分已链接到了binary中代码段，某些仍然为0
#  对 imp为0 的__la_symbol_ptr，将其链接到stub_helper的地址
#  同时，hook stub_helper，做合适的返回就好

def hook_stubs(state):
    stub_helper = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__stub_helper').min_addr
    __la_symbol_ptr = MachO.pd.macho.get_segment_by_name('__DATA').get_section_by_name('__la_symbol_ptr')
    for ptr in range(__la_symbol_ptr.min_addr, __la_symbol_ptr.max_addr, 8):
        symbol = MachO.pd.macho.get_symbol_by_address_fuzzy(ptr)
        if symbol:
            # print hex(ptr), symbol.name
            if symbol.name == '_objc_msgSend':
                bv = state.solver.BVV(ptr, 64).reversed
                state.memory.store(ptr, bv)
                MachO.pd.project.hook(ptr, msgSend)
            elif symbol.name == '_objc_autoreleaseReturnValue':
                bv = state.solver.BVV(ptr, 64).reversed
                state.memory.store(ptr, bv)
                MachO.pd.project.hook(ptr, ReturnHook)
            else:
                bv = state.solver.BVV(stub_helper, 64).reversed
                state.memory.store(ptr, bv)
        else:
            # print hex(ptr), hex(state.mem[ptr].long.concrete)
            pass
    MachO.pd.project.hook(stub_helper, stubHelper)

    # for symbol in Data.pd.macho.get_symbol('_objc_msgSend'):
    #     for addr in symbol.bind_xrefs:



