from Data.binary import MachO


def ret_cond(state):
    # return state.eval(state.regs.rax, cast_to=str) == 'AAAA' and 0x8004 in state.inspect.backtrace
    hooks = [0x100b4ab20, 0x100B4ABD8, 0x1007D8578]
    return state.solver.eval(state.ip) not in hooks and state.inspect.exit_jumpkind == 'Ijk_Ret'

def loop_filter(state):
    function_start = MachO.pd.analyzer.current_f.start
    history = state.history
    jmp_target = state.solver.eval(state.inspect.exit_target)
    while (history.addr != function_start):
        state_addr = history.addr
        if jmp_target == state_addr:
            # print "Loop at {}".format(jmp_target)
            # state.inspect.exit_guard = state.solver.BVV(0, 64)
            state.inspect.exit_guard = state.solver.BVV(int(state.inspect.exit_guard.is_false()), 64) # reverse
            break
        history = history.parent

def log_jmp(state):
    # print "ip:", state.ip,
    # print 'target', hex(state.solver.eval(state.inspect.exit_target)),
    # print 'guard', state.inspect.exit_guard,
    # print 'jumpkind', state.inspect.exit_jumpkind
    # print "return value: ", state.solver.eval(state.regs.x0)
    print "from {} to {}, guard {}".format(hex(state.solver.eval(state.ip)), hex(state.solver.eval(state.inspect.exit_target)), state.inspect.exit_guard)
    print state.regs.w21


def branch(state):
    # log_jmp(state)
    text = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text')
    jmp_target = state.solver.eval(state.inspect.exit_target)

    if state.inspect.exit_jumpkind == 'Ijk_Boring' and jmp_target < text.max_addr:
        loop_filter(state)

    if jmp_target == MachO.pd.analyzer.next_func_addr:
        # print "Log ret value at {} : {}".format(state.ip, state.solver.eval(state.regs.x0))
        MachO.pd.analyzer.current_f.setRetVal(state.solver.eval(state.regs.x0))
        # state.inspect.exit_guard = state.solver.BVV(0, 64)
        state.solver.BVV(int(state.inspect.exit_guard.is_false()), 64)
    if state.solver.eval(state.inspect.exit_target) == 0:
        # print "Log ret value : {}".format(state.solver.eval(state.regs.x0))
        MachO.pd.analyzer.current_f.setRetVal(state.solver.eval(state.regs.x0))

def stubs_construct(state):
    # print "mem read at: ", state.inspect.mem_read_address
    stub_code_addr = state.addr - 4
    if stub_code_addr not in MachO.pd.stubs:
        MachO.pd.stubs[stub_code_addr] = MachO.pd.macho.get_symbol_by_address_fuzzy(state.solver.eval(state.inspect.mem_read_address))

