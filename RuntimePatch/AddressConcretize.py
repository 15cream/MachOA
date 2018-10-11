from RuntimePatch.Utils import *
from angr.errors import SimMemoryAddressError


def mem_resolve(state):
    try:
        expr = state.inspect.address_concretization_expr
        result = state.inspect.address_concretization_result
        if result and len(result) == 1:
            if expr.op == '__add__':
                instance = expr.args[0]
                var_offset = expr.args[1]
                if instance.op == 'BVS' and var_offset.op == 'BVV':
                    classname = None
                    if '@' in instance.args[0]:
                        classname = instance.args[0].split('"')[-2]
                    elif 'instance' in instance.args[0]:
                        classname = instance.args[0].split('_')[0]
                    if classname:
                        state.memory.store(result[0], resolve_var(state, classname=classname, offset=state.solver.eval(var_offset)))
    except SimMemoryAddressError:
        print '!!!!!!!!!!!!!!SimMemoryAddressError'


