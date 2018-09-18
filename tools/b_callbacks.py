from Data.binary import MachO


def loop_filter(state):
    function_start = MachO.pd.task.current_f.start
    history = state.history
    jmp_target = state.solver.eval(state.inspect.exit_target)
    while (history.addr != function_start):
        state_addr = history.addr
        if jmp_target == state_addr:
            state.inspect.exit_guard = state.solver.BVV(int(state.inspect.exit_guard.is_false()), 64)  # add reversed constraint
            break
        history = history.parent


def branch(state):
    text = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text')
    jmp_target = state.solver.eval(state.inspect.exit_target)

    if state.inspect.exit_jumpkind == 'Ijk_Boring' and jmp_target < text.max_addr:
        loop_filter(state)

    if jmp_target == MachO.pd.task.next_func_addr:
        MachO.pd.analyzer.current_f.setRetVal(state.solver.eval(state.regs.x0))
        state.solver.BVV(int(state.inspect.exit_guard.is_false()), 64)

    if state.solver.eval(state.inspect.exit_target) == 0:
        MachO.pd.task.current_f.setRetVal(state.solver.eval(state.regs.x0))


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









