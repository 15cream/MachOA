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
            print "Loop at {}".format(jmp_target)
            state.inspect.exit_guard = state.solver.BVV(1, 64) > 5
            break
        history = history.parent


def get_retval(state):
    # print "ip:", state.ip,
    # print 'target', state.inspect.exit_target,
    # print 'guard', state.inspect.exit_guard,
    # print 'jumpkind', state.inspect.exit_jumpkind,
    # print "return value: ", state.solver.eval(state.regs.x0)
    function_start = MachO.pd.analyzer.current_f.start
    text = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text')
    history = state.history
    jmp_target = state.solver.eval(state.inspect.exit_target)
    if state.inspect.exit_jumpkind == 'Ijk_Boring' and jmp_target < text.max_addr:
        # state.inspect.exit_guard = state.solver.BVV(1, 64) < 5
        # print "jump from {} to {}, guard: {}, eval: {}".format(state.ip, state.inspect.exit_target,
        #                                                        state.inspect.exit_guard,
        #                                                        state.solver.eval(state.inspect.exit_guard))
        loop_filter(state)

    elif jmp_target == MachO.pd.analyzer.next_func_addr:
        state.inspect.exit_guard = state.solver.BVV(1, 64) > 5



def stubs_construct(state):
    # print "mem read at: ", state.inspect.mem_read_address
    stub_code_addr = state.addr - 4
    if stub_code_addr not in MachO.pd.stubs:
        MachO.pd.stubs[stub_code_addr] = MachO.pd.macho.get_symbol_by_address_fuzzy(state.solver.eval(state.inspect.mem_read_address))

