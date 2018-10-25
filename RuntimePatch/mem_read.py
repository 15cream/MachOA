__author__ = 'gjy'
from Data.OCivar import IVar
import claripy


def mem_read(state):
    ea = state.inspect.mem_read_address
    if state.solver.eval(ea) in IVar.ivars:
        ptr = state.solver.eval(ea)
        ivar_expr = "{}@ivar".format(hex(ptr))
        state.inspect.mem_read_expr = claripy.BVS(ivar_expr, 32, uninitialized=True)
        # state.inspect.mem_read_expr = claripy.BVV(ptr, 64)