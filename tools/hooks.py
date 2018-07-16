__author__ = 'gjy'
from angr import SimProcedure
from Data.binary import MachO
import claripy


class msgSend(SimProcedure):
    def run(self):
        state = self.state
        src_state = state.history.parent.parent
        bl_addr = src_state.addr + src_state.recent_instruction_count * 4
        invoke = MachO.resolve_invoke(state, bl_addr)
        # x0 = state.registers.load('x0')
        newval = claripy.BVS('uninitialized_x0', 64)
        # state.registers.store('x0', newval)
        return newval


class stubHelper(SimProcedure):
    def run(self):
        # print "Stub helper"
        state = self.state
        # x0 = state.registers.load('x0')
        newval = claripy.BVS('uninitialized_x0', 64)
        # state.registers.store('x0', newval)
        return newval


class ReturnHook(SimProcedure):
    def run(self):
        state = self.state
        src_state = state.history.parent.parent
        ret_addr = src_state.addr + src_state.recent_instruction_count * 4
        x0 = state.registers.load('x0')
        print '{} return value: {} .'.format(hex(ret_addr), state.solver.eval(x0))
        return x0
