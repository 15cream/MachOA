__author__ = 'gjy'
from Data.OCivar import IVar
from Data.MachO import MachO
import claripy


def mem_read(state):
    ea = state.inspect.mem_read_address
    length = state.inspect.mem_read_length * 8
    ptr = state.solver.eval(ea)
    if ptr in IVar.ivars:
        ivar_expr = "{}@ivar".format(hex(ptr))
        state.inspect.mem_read_expr = claripy.BVS(ivar_expr, length, uninitialized=True)
        # IVar.ivars[ptr].add_set_accessor(state)
        # state.inspect.mem_read_expr = claripy.BVV(ptr, 64)
    elif MachO.pd.segdata['common'] and ptr in range(MachO.pd.segdata['common'].min_addr, MachO.pd.segdata['common'].max_addr):
        state.inspect.mem_read_expr = claripy.BVS('{}@uninitialized_common'.format(hex(ptr)), length, uninitialized=True)
    elif ptr in range(MachO.pd.segdata['bss'].min_addr, MachO.pd.segdata['bss'].max_addr):
        state.inspect.mem_read_expr = claripy.BVS('{}@uninitialized_bss'.format(hex(ptr)), length, uninitialized=True)