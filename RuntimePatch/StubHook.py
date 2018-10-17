__author__ = 'gjy'
from angr import SimProcedure

from Data.CONSTANTS import *
from RuntimePatch.Utils import *
from RuntimePatch.msgSend import msgSend


class StubHelper(SimProcedure):

    def run(self):
        state = self.state
        src_state = state.history.parent.parent
        addr = src_state.addr + src_state.recent_instruction_count * 4
        symbol = MachO.pd.stubs[state.history.parent.addr]

        if symbol.name in objc_symbols:
            return state.registers.load('x0')
        elif symbol.name in msgSends:
            msg = msgSend(state)
            ret = msg.resolve_in_context()
            if type(ret) == int or type(ret) == long:
                if IPC:
                    self.call(ret, args=[], continue_at='ret_from_msgSend', cc=None)
                else:
                    return claripy.BVS("RetFrom_" + hex(addr), 64, uninitialized=True)
                    # return claripy.BVS(OCFunction.meth_data[ret]['name'], 64, uninitialized=True)
            else:
                return ret
        elif symbol.name in dispatch:
            print "There is a dispatch"
            # base = state.regs.x1
            # for i in range(1, 6):
            #     ea = state.mem[base + 8 * i].long.concrete
            #     if ea in MachO.pd.macho.lc_function_starts:
            #         return ea
        else:
            # MachO.pd.task.cg.insert_invoke(addr, symbol, state, args=resolve_args(state, symbol=symbol))
            return claripy.BVS("RetFrom_" + hex(addr), 64, uninitialized=True)

    def ret_from_msgSend(self):
        print 'I just jumped to a meth_imp and returned'

