# coding=utf-8
__author__ = 'gjy'
from Data.OCivar import IVar
from Data.MachO import MachO, BSS
from Data.CONSTANTS import *
import claripy


def mem_read(state):
    
    resolved_data = None
    length = state.inspect.mem_read_length * 8
    ptr = state.solver.eval(state.inspect.mem_read_address)
    
    if ptr in IVar.ivars:
        ivar = IVar.ivars[ptr]
        state.inspect.mem_read_expr = claripy.BVS(FORMAT_IVAR_OFFSET.format(ptr=hex(ptr)), length, uninitialized=True)
        print 'T'

    elif MachO.pd.segdata['common'] and ptr in range(MachO.pd.segdata['common'].min_addr, MachO.pd.segdata['common'].max_addr):
        state.inspect.mem_read_expr = claripy.BVS(FORMAT_COMMON_DATA.format(ptr=hex(ptr)), length, uninitialized=True)
    
    elif ptr in range(MachO.pd.segdata['bss'].min_addr, MachO.pd.segdata['bss'].max_addr):
        state.inspect.mem_read_expr = BSS.get(ptr).load(length)


def mem_write(state):
    resolved_data = None
    length = state.inspect.mem_write_length * 8
    ptr = state.solver.eval(state.inspect.mem_write_address)

    if ptr in IVar.ivars:
        ivar = IVar.ivars[ptr]
        resolved_data = FORMAT_IVAR_OFFSET.format(ptr=hex(ptr))

    elif MachO.pd.segdata['common'] and ptr in range(MachO.pd.segdata['common'].min_addr,
                                                     MachO.pd.segdata['common'].max_addr):
        resolved_data = FORMAT_COMMON_DATA.format(ptr=hex(ptr))

    elif ptr in range(MachO.pd.segdata['bss'].min_addr, MachO.pd.segdata['bss'].max_addr):
        # 并不改变写入值，只是对写入值进行记录
        BSS.get(ptr).store(state.inspect.mem_write_expr)

    
# ivar_expr = "{}@ivar".format(hex(ptr))
# IVar.ivars[ptr].add_set_accessor(state)
# state.inspect.mem_read_expr = claripy.BVV(ptr, 64)