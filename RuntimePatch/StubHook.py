__author__ = 'gjy'
from angr import SimProcedure

from Data.CONSTANTS import *
from RuntimePatch.Utils import *
from RuntimePatch.message import Message


class StubHelper(SimProcedure):

    def run(self):
        dispatch_state = self.state
        invoke_state = dispatch_state.history.parent.parent
        invoke_ea = invoke_state.addr + invoke_state.recent_instruction_count * 4
        symbol = MachO.pd.stubs[dispatch_state.history.parent.addr]
        lib = symbol.library_name

        if lib == '/usr/lib/libobjc.A.dylib':
            if symbol.name == "_objc_msgSend":
                msg = Message(dispatch_state, simprocedure_handler=self)
                msg.send2()

            elif symbol.name == "_objc_msgSendSuper2":
                pass
        else:
            MachO.pd.task.cg.insert_invoke(invoke_ea, symbol, dispatch_state, args=resolve_args(dispatch, symbol=symbol))
            return dispatch_state.registers.load('x0')

    def ret_from_msgSend(self):
        print 'I just jumped to a meth_imp and returned'

    # origin
    def run_(self):
        state = self.state
        src_state = state.history.parent.parent
        addr = src_state.addr + src_state.recent_instruction_count * 4
        symbol = MachO.pd.stubs[state.history.parent.addr]

        if symbol.name in objc_symbols:
            return state.registers.load('x0')
        elif symbol.name in msgSends:
            msg = Message(state)
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




