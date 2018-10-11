from Data.MachO import MachO
import claripy


def branch_check(state):
    text = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text')
    jmp_target = state.solver.eval(state.inspect.exit_target)

    if state.inspect.exit_jumpkind == 'Ijk_Ret' and jmp_target in MachO.pd.macho.lc_function_starts:
        state.inspect.exit_guard = claripy.false
        return
    if target_invalid(state):
        state.inspect.exit_target = state.regs.lr
        state.inspect.exit_jumpkind = 'Ijk_Boring'

    elif state.inspect.exit_jumpkind == 'Ijk_Boring' and jmp_target < text.max_addr:
        if loop_found(state):
            return

    #  RET, Sub call, method call
    state.inspect.exit_guard = claripy.true
    state.__setattr__('help', True)


def target_invalid(state):
    expr = str(state.inspect.exit_target)
    if 'mem_f' in expr:
        # jmp target cannot be mem_address
        return True
    return False


def loop_found(state):
    jmp_target = state.solver.eval(state.inspect.exit_target)
    if jmp_target in MachO.pd.macho.lc_function_starts:
        # method call or subroutine jmp
        return False
    history = state.history
    while history:
        if jmp_target == history.addr:
            state.inspect.exit_guard = claripy.false
            return True
        history = history.parent
    return False






