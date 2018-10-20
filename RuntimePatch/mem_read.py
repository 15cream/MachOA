__author__ = 'gjy'
from Data.OCivar import IVar


def mem_read(state):
    ea = state.inspect.mem_read_address
    if state.solver.eval(ea) in IVar.ivars:
        ptr = state.solver.eval(ea)
        ivar = IVar.ivars[ptr]

        print ea