from Data.binary import MachO
from Data.function import Function
import claripy


def loop_filter(state):
    history = state.history
    jmp_target = state.solver.eval(state.inspect.exit_target)
    if jmp_target in MachO.pd.macho.lc_function_starts:
        return False
    while history:
        state_addr = history.addr
        if jmp_target == state_addr:
            # state.inspect.exit_guard = state.solver.BVV(int(state.inspect.exit_guard.is_false()), 64)  # add reversed constraint
            state.inspect.exit_guard = claripy.false
            return True
        history = history.parent
    return False


def branch(state):
    text = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text')
    jmp_target = state.solver.eval(state.inspect.exit_target)
    jmp_target_resolve(state)

    if state.inspect.exit_jumpkind == 'Ijk_Boring' and jmp_target < text.max_addr:
        if loop_filter(state):
            return

    state.inspect.exit_guard = claripy.true
    state.__setattr__('help', True)

    if jmp_target in MachO.pd.macho.lc_function_starts:
        # MachO.pd.task.current_f.setRetVal(state.solver.eval(state.regs.x0))
        # state.solver.BVV(int(state.inspect.exit_guard.is_false()), 64)
        return

    if jmp_target == 0:
        # MachO.pd.task.current_f.setRetVal(state.solver.eval(state.regs.x0))
        return

# if jmp_target in Function.subroutines:
    #     print 'BREAK DOWN AT SUB_{}'.format(hex(jmp_target))
    #     state.inspect.exit_guard = claripy.false


def jmp_target_resolve(state):
    expr = str(state.inspect.exit_target)
    if 'mem_f' in expr:
        state.inspect.exit_target = state.regs.lr
        state.inspect.exit_guard = claripy.true
        state.inspect.exit_jumpkind == 'Ijk_Boring'


def mem_resolve(state):
    expr = state.inspect.address_concretization_expr
    result = state.inspect.address_concretization_result
    if result and len(result) == 1:
        if expr.op == '__add__':
            # Not complete
            instance = expr.args[0]
            var_offset = expr.args[1]
            if instance.op == 'BVS' and var_offset.op == 'BVV':
                classname = None
                if '@' in instance.args[0]:
                    classname = instance.args[0].split('"')[-2]
                elif 'instance' in instance.args[0]:
                    classname = instance.args[0].split('_')[0]
                if classname:
                    state.memory.store(result[0], MachO.pd.resolve_var(state, classname=classname, offset=state.solver.eval(var_offset)))

def mem_read_resolve(state):
    expr = state.inspect.mem_read_expr
    addr = state.inspect.mem_read_address
    # val = state.memory.load(state.inspect.mem_read_address)
    if '0x7fff' in str(addr):  # read value from stack

            state.memory.store(addr, claripy.BVS('EIP', 64, uninitialized=True).reversed)






