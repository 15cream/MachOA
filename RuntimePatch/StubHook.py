# coding=utf-8
__author__ = 'gjy'
from angr import SimProcedure
from Data.CONSTANTS import *
from tools.common import block_excess
from Data.data import *
from Data.OCivar import *
from Data.data import Block
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
                    ivar = IVar.ivars[int(m.group('ptr'), 16)]
                    # ivar.add_record(AccessedRecord(invoke_ea, symbol.name, value=dispatch_state.regs.x2))

            elif symbol.name in getProperty:
                print 'Here'
        elif '_dispatch_' in symbol.name:
            # base = state.regs.x1
            # for i in range(1, 6):
            #     ea = state.mem[base + 8 * i].long.concrete
            #     if ea in MachO.pd.macho.lc_function_starts:
            #         return ea
            block = None
            for i in range(0, 5):
                block = Block(self.state, self.state.registers.load('x{}'.format(i)))
                if block.subroutine:
                    break
            if block.subroutine and not block_excess(MachO.pd.task.p, block.subroutine):
                self.state.regs.x0 = block.data_ea
                self.jump(block.subroutine)
            return
        else:
            # args = []
            # for i in range(0, 6):
            #     reg_name = 'x{}'.format(i)
            #     reg = Data(self.state, reg=dispatch_state.regs.get(reg_name))
            #     args.append(reg)
            # MachO.pd.task.cg.insert_invoke(invoke_ea, symbol, dispatch_state, args=args)
            return dispatch_state.registers.load('x0')

    def ret_from_msgSend(self):
        print 'I just jumped to a meth_imp and returned'
        return


def analyze_lazy_bind_invoke(dispatch_state, ptr):
    """
    这一段代码是没有经过stub_helper跳转的代码
    :param dispatch_state:
    :param ptr:
    :return:
    """
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

