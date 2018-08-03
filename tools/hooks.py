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
        x0_name = "ret_from_" + hex(bl_addr)
        newval = claripy.BVS(x0_name, 64)
        # state.registers.store('x0', newval)
        return newval


class stubHelper(SimProcedure):
    def run(self):
        # print "Stub helper"
        state = self.state
        symbol = MachO.pd.stubs[state.history.parent.addr]
        if symbol.name == '_objc_retainAutoreleasedReturnValue':
            return state.registers.load('x0')
        elif symbol.name == '_objc_autoreleaseReturnValue':
            return state.registers.load('x0')
        elif symbol.name == '_objc_retain':
            return state.registers.load('x0')
        elif symbol.name == '_objc_release':
            return state.registers.load('x0')
        elif symbol.name == '_objc_msgSend':
            src_state = state.history.parent.parent
            bl_addr = src_state.addr + src_state.recent_instruction_count * 4
            MachO.resolve_invoke(state, bl_addr)
            x0_name = "ret_from_" + hex(bl_addr)
            return claripy.BVS(x0_name, 64)
        else:
            x0_name = "ret_from_" + symbol.name
            newval = claripy.BVS(x0_name, 64)
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
