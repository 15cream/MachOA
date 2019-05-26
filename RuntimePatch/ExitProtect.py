#coding=utf-8
from Data.MachO import MachO
from Data.OCFunction import OCFunction
from Data.CONSTANTS import *
from Data.data import *
from StubHook import analyze_lazy_bind_invoke
from tools.common import block_excess
import claripy


def branch_check(state):
    """

    :param state:
    :return:
    """
    text = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text')
    jmp_target = state.solver.eval(state.inspect.exit_target)
    src = state.addr
    # if state.inspect.exit_guard is not claripy.true:
    #     constraint = str(state.inspect.exit_guard).strip('<>')
    #     state.globals['added_constraints'].append(constraint)

    if not STUB_HOOK:
        if jmp_target in MachO.pd.stubs:
            analyze_lazy_bind_invoke(state, jmp_target)
            if state.solver.eval(state.regs.lr) in MachO.pd.macho.lc_function_starts:
                state.inspect.exit_target = state.solver.BVV(0, 64)
                jmp_target = 0
            else:
                state.inspect.exit_target = state.regs.lr

    # 如果目标地址大于代码段，一般没什么好看的。
    if jmp_target > text.max_addr:
        return

    # 如果目标地址为０，默认方法体结束，x0中可能存在返回值。
    if jmp_target == 0:
        if 'start_func_object' in state.globals:
            ret_value = Data(state, bv=state.regs.get('x0'))
            if src > text.max_addr:
                if STUB_HOOK:
                    ret_state = state.history.parent.parent  # invoke_context_state -> msgSend_stub -> stub_helper
                    ret_ea = ret_state.addr + ret_state.recent_instruction_count * 4
                else:
                    ret_ea = src
            else:
                ret_ea = src
            state.globals['start_func_object'].ret.add(ret_value.expr)
            MachO.pd.task.cg.add_ret_node(ret_ea, state, ret_value.expr)
        return

    # 异常状态，当类型为返回但返回地址为方法起始地址时，设置跳转条件为假
    if state.inspect.exit_jumpkind == 'Ijk_Ret' and jmp_target in MachO.pd.macho.lc_function_starts:
        state.inspect.exit_guard = claripy.false
        return

    # 如果跳转无效，例如BLR时目标地址无效，将跳转地址设置为lr值。
    if target_invalid(state):
        state.inspect.exit_target = state.regs.lr
        state.inspect.exit_jumpkind = 'Ijk_Boring'
        state.inspect.exit_guard = claripy.true
        state.__setattr__('help', True)

    # 如果跳转地址为oc方法，在没有开IPC时是不被允许的，但可以是subroutine。
    if jmp_target in OCFunction.meth_list:
        if not IPC:
            if jmp_target in OCFunction.oc_function_set:
                state.inspect.exit_target = state.regs.lr
                return
            elif jmp_target in OCFunction.meth_list:
                if block_excess(MachO.pd.task.p, jmp_target):
                    state.inspect.exit_target = state.regs.lr
                    return

    # 最普通的跳转，检测是否存在循环。
    if state.inspect.exit_jumpkind == 'Ijk_Boring' and jmp_target < text.max_addr:
        if loop_found(state):
            state.inspect.exit_guard = claripy.false
            state.__setattr__('help', False)
            return

    #  RET, Sub call, method call
    # state.inspect.exit_guard = claripy.true
    state.__setattr__('help', True)


def target_invalid(state):
    """
    You should evaluate the target, code segment or database segment.
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


def branch_check2(state):
    """

    :param state:
    :return:
    """
    text = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text')
    jmp_target = state.solver.eval(state.inspect.exit_target)
    src = state.addr

    # 避免一不小心过程间分析了，或者是angr没有做好代码块划分
    if state.solver.eval(state.regs.lr) in MachO.pd.macho.lc_function_starts:
        state.inspect.exit_target = state.solver.BVV(0, 64)

    if jmp_target in MachO.pd.stubs:
        jmp_target = state.solver.eval(state.regs.lr)

    if src > MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text').max_addr:
        return

    # print 'jump from {} to {}'.format(hex(src), hex(jmp_target))
    if jmp_target in state.globals['jmp_target']:
        state.globals['jmp_target'][jmp_target].append(src)
    else:
        state.globals['jmp_target'][jmp_target] = [src]




