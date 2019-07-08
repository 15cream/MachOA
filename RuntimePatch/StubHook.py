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
from RuntimePatch.libs.libobjcA import handle_objc_loadWeakRetained
from SecCheck.cryptographic import CryptoChecker


class StubHelper(SimProcedure):

    def run(self):
        dispatch_state = self.state
        invoke_state = dispatch_state.history.parent.parent
        invoke_ea = invoke_state.addr + invoke_state.recent_instruction_count * 4
        symbol = MachO.pd.stubs[dispatch_state.history.parent.addr]
        lib = symbol.library_name

        if lib == '/usr/lib/libobjc.A.dylib':
            if symbol.name == "_objc_msgSend":
                Message(dispatch_state, invoke_ea, simprocedure_handler=self).send2()
            elif symbol.name == "_objc_msgSendSuper2":
                Message(dispatch_state, invoke_ea, simprocedure_handler=self, send_super=True).send2()
            elif symbol.name == '_objc_loadWeakRetained':
                handle_objc_loadWeakRetained(dispatch_state)
            elif symbol.name in setProperty:
                m = re.search('<BV\d+ \(<ea:0x(?P<ptr>[0-9a-f]+)L>\)IVAR_OFFSET.+', str(dispatch_state.regs.x3.args[0]))
                if m:
                    ivar = IVar.ivars[int(m.group('ptr'), 16)]
                    ivar.add_record(AccessedRecord(dispatch_state, invoke_ea, symbol.name, value=dispatch_state.regs.x2))
            elif symbol.name in getProperty:
                pass
        elif lib == '/usr/lib/libSystem.B.dylib':
            if '_dispatch_' in symbol.name:  # TODO 检查是否不同的dispatch，参数不同
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
            elif symbol.name in CryptoChecker.crypt_funcs:
                args = []
                for i in range(0, 6):
                    reg_name = 'x{}'.format(i)
                    bv = Data(self.state, bv=dispatch_state.regs.get(reg_name))
                    args.append(bv)
                node = MachO.pd.task.cg.insert_invoke(invoke_ea, symbol.name, dispatch_state, args=args)
                CryptoChecker.check(MachO.pd.task.cg, node, args)
                # NOTE: 如果只是检测加密函数的使用，不用检测接下来，那么到此结束；
                # 如果是其他分支的加密函数，会在其他分支再次解析的，不会影响上下文敏感性。
                # self.jump(self.state.solver.BVV(0, 64))


        else:
            # args = []
            # for i in range(0, 6):
            #     reg_name = 'x{}'.format(i)
            #     bv = Data(self.state, bv=dispatch_state.regs.get(reg_name))
            #     args.append(bv)
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
            Message(dispatch_state, invoke_ea).send2()
        elif symbol.name == "_objc_msgSendSuper2":
            Message(dispatch_state, invoke_ea, send_super=True).send2()
        elif symbol.name in setProperty:
            m = re.search('<BV\d+ \(<ea:0x(?P<ptr>[0-9a-f]+)L>\)IVAR_OFFSET.+', str(dispatch_state.regs.x3.args[0]))
            if m:
                ivar = IVar.ivars(int(m.group('ptr'), 16))
                ivar.add_record(AccessedRecord(invoke_ea, symbol.name, value=dispatch_state.regs.x2))
        elif symbol.name in getProperty:
            pass
    else:
        args = []
        for i in range(0, 6):
            reg_name = 'x{}'.format(i)
            reg = Data(dispatch_state, bv=dispatch_state.regs.get(reg_name))
            args.append(reg)
        MachO.pd.task.cg.insert_invoke(invoke_ea, symbol, dispatch_state, args=args)

