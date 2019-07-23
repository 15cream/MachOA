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
from RuntimePatch.libs.libobjcA import *
from Results.call_sites import CallSite


class StubHelper(SimProcedure):

    def run(self):
        dispatch_state = self.state
        invoke_state = dispatch_state.history.parent.parent
        invoke_ea = invoke_state.addr + invoke_state.recent_instruction_count * 4
        symbol = MachO.pd.stubs[dispatch_state.history.parent.addr]
        lib = symbol.library_name
        node = None

        if lib == '/usr/lib/libobjc.A.dylib':  # 这个是运行时库的代码，如果要处理函数调用需要模拟其功能
            if symbol.name == "_objc_msgSend":
                msg = Message(dispatch_state, invoke_ea, simprocedure_handler=self)
                node = msg.send2()
            elif symbol.name == "_objc_msgSendSuper2":
                msg = Message(dispatch_state, invoke_ea, simprocedure_handler=self, send_super=True)
                node = msg.send2()
            elif symbol.name in objcA_handlers:
                objcA_handlers[symbol.name](dispatch_state)
            elif symbol.name in setProperty:
                m = re.search('<BV\d+ \(<ea:0x(?P<ptr>[0-9a-f]+)L>\)IVAR_OFFSET.+', str(dispatch_state.regs.x3.args[0]))
                if m:
                    ivar = IVar.ivars[int(m.group('ptr'), 16)]
                    ivar.add_record(AccessedRecord(dispatch_state, invoke_ea, symbol.name, value=dispatch_state.regs.x2))

        elif lib == '/usr/lib/libSystem.B.dylib':
            if '_dispatch_' in symbol.name:  # TODO 检查是否不同的dispatch，参数不同
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
                args = []
                for i in range(0, 7):
                    reg_name = 'x{}'.format(i)
                    bv = Data(self.state, bv=dispatch_state.regs.get(reg_name))
                    args.append(bv)
                node = MachO.pd.task.cg.insert_invoke(invoke_ea, symbol.name, dispatch_state, args=args)
                if symbol.name in MachO.pd.symbol_and_stub:
                    MachO.pd.task.cg.g.nodes[node]['handler'] = MachO.pd.symbol_and_stub[symbol.name]
                # self.jump(self.state.solver.BVV(0, 64))
        else:
            args = []
            for i in range(0, 6):
                reg_name = 'x{}'.format(i)
                bv = Data(self.state, bv=dispatch_state.regs.get(reg_name))
                args.append(bv)
            node = MachO.pd.task.cg.insert_invoke(invoke_ea, symbol, dispatch_state, args=args)
            x0 = FORMAT_INSTANCE.format(data_type='unknown', instance_type='RET', ptr=hex(invoke_ea),
                                        name=symbol.name)
            dispatch_state.regs.x0 = dispatch_state.solver.BVS(x0, 64)
            if symbol.name in MachO.pd.symbol_and_stub:
                MachO.pd.task.cg.g.nodes[node]['handler'] = MachO.pd.symbol_and_stub[symbol.name]
            # return dispatch_state.registers.load('x0')

        if node:
            CallSite.collect(MachO.pd.task.cg, node)

    def ret_from_msgSend(self):
        print 'I just jumped to a meth_imp and returned'
        return


# 另一种尝试
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

    else:
        args = []
        for i in range(0, 6):  # TODO 需要收集更多函数原型
            reg_name = 'x{}'.format(i)
            reg = Data(dispatch_state, bv=dispatch_state.regs.get(reg_name))
            args.append(reg)
        MachO.pd.task.cg.insert_invoke(invoke_ea, symbol, dispatch_state, args=args)

