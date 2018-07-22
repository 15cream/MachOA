from Data.binary import MachO


def ret_cond(state):
    # return state.eval(state.regs.rax, cast_to=str) == 'AAAA' and 0x8004 in state.inspect.backtrace
    hooks = [0x100b4ab20, 0x100B4ABD8, 0x1007D8578]
    return state.solver.eval(state.ip) not in hooks and state.inspect.exit_jumpkind == 'Ijk_Ret'


def get_retval(state):
    print "ip:", state.ip,
    print 'target', state.inspect.exit_target,
    print 'guard', state.inspect.exit_guard,
    print 'jumpkind', state.inspect.exit_jumpkind,
    print "return value: ", state.solver.eval(state.regs.x0)


def stubs_construct(state):
    # print "mem read at: ", state.inspect.mem_read_address
    stub_code_addr = state.addr - 4
    if stub_code_addr not in MachO.pd.stubs:
        MachO.pd.stubs[stub_code_addr] = MachO.pd.macho.get_symbol_by_address_fuzzy(state.solver.eval(state.inspect.mem_read_address))

