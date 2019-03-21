__author__ = 'gjy'
import re
from angr import SimProcedure

from Data.CONSTANTS import *
from Data.data import *
from Data.OCivar import *
from RuntimePatch.Utils import *
from RuntimePatch.message import Message
from RuntimePatch.AddressConcretize import mem_resolve2


class StubHelper(SimProcedure):

    def run(self):
        dispatch_state = self.state
        invoke_state = dispatch_state.history.parent.parent
        invoke_ea = invoke_state.addr + invoke_state.recent_instruction_count * 4
        symbol = MachO.pd.stubs[dispatch_state.history.parent.addr]
        lib = symbol.library_name

        if lib == '/usr/lib/libobjc.A.dylib':
            if symbol.name == "_objc_msgSend":
                msg = Message(dispatch_state, invoke_ea, simprocedure_handler=self)
                msg.send2()
                # print hex(invoke_ea), msg.description

            elif symbol.name == "_objc_msgSendSuper2":
                msg = Message(dispatch_state, invoke_ea, simprocedure_handler=self, send_super=True)
                msg.send2()
                # print hex(invoke_ea), msg.description

            elif symbol.name == '_objc_loadWeakRetained':
                mem_resolve2(dispatch_state)

            elif symbol.name in setProperty:
                print 'Here'
                m = re.search('<BV\d+ \(<ea:0x(?P<ptr>[0-9a-f]+)L>\)IVAR_OFFSET.+', str(dispatch_state.regs.x3.args[0]))
                if m:
                    ivar = IVar.ivars(int(m.group('ptr'), 16))
                    ivar.add_record(AccessedRecord(invoke_ea, symbol.name, value=dispatch_state.regs.x2))

            elif symbol.name in getProperty:
                print 'Here'

        else:
            args = []
            for i in range(0, 6):
                reg_name = 'x{}'.format(i)
                reg = Data(self.state, reg=dispatch_state.regs.get(reg_name))
                args.append(reg)
            MachO.pd.task.cg.insert_invoke(invoke_ea, symbol, dispatch_state, args=args)
            return dispatch_state.registers.load('x0')

    def ret_from_msgSend(self):
        print 'I just jumped to a meth_imp and returned'
        return

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
            # ret = msg.resolve_in_context()
            ret = 0x10031DF34
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


def analyze_lazy_bind_invoke(dispatch_state, ptr):
    invoke_ea = dispatch_state.history.addr + dispatch_state.history.recent_instruction_count * 4
    symbol = MachO.pd.stubs[ptr]
    lib = symbol.library_name

    if lib == '/usr/lib/libobjc.A.dylib':
        if symbol.name == "_objc_msgSend":
            msg = Message(dispatch_state, invoke_ea)
            msg.send2()
            # print hex(invoke_ea), msg.description

        elif symbol.name == "_objc_msgSendSuper2":
            msg = Message(dispatch_state, invoke_ea, send_super=True)
            msg.send2()
            # print hex(invoke_ea), msg.description

        elif symbol.name in setProperty:
            print 'Here'
            m = re.search('<BV\d+ \(<ea:0x(?P<ptr>[0-9a-f]+)L>\)IVAR_OFFSET.+', str(dispatch_state.regs.x3.args[0]))
            if m:
                ivar = IVar.ivars(int(m.group('ptr'), 16))
                ivar.add_record(AccessedRecord(invoke_ea, symbol.name, value=dispatch_state.regs.x2))

        elif symbol.name in getProperty:
            print 'Here'

    else:
        args = []
        for i in range(0, 6):
            reg_name = 'x{}'.format(i)
            reg = Data(dispatch_state, reg=dispatch_state.regs.get(reg_name))
            args.append(reg)
        MachO.pd.task.cg.insert_invoke(invoke_ea, symbol, dispatch_state, args=args)

