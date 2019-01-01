from Data.MachO import MachO
from Data.OCFunction import OCFunction
from Data.CONSTANTS import *
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
        state.inspect.exit_guard = claripy.true
        state.__setattr__('help', True)

    if state.inspect.exit_jumpkind == 'Ijk_Boring' and jmp_target < text.max_addr:
        if loop_found(state):
            state.inspect.exit_guard = claripy.false
            state.__setattr__('help', False)
            return

    if jmp_target in OCFunction.meth_list:
        if not IPC:
            #  must be subroutines
            state.inspect.exit_target = state.regs.lr

    #  RET, Sub call, method call
    # state.inspect.exit_guard = claripy.true
    # state.__setattr__('help', True)


def target_invalid(state):
    """
    You should evaluate the target, code segment or data segment.
    :param state:
    :return:
    """
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






