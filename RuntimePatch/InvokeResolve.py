__author__ = 'gjy'
from angr import SimProcedure

from Data.CONSTANTS import *

from BinaryPatch.Utils import *

from RuntimePatch.Utils import *


class StubHelper(SimProcedure):

    def run(self):
        state = self.state
        # src_state = state.history.parent.parent
        # addr = src_state.addr + src_state.recent_instruction_count * 4
        symbol = MachO.pd.stubs[state.history.parent.addr]
        if symbol.name in objc_symbols:
            return state.registers.load('x0')
        else:
            if symbol.name in msgSend:
                ret = self.resolve_invoke(state, type=MSGSEND)
            else:
                ret = self.resolve_invoke(state, type=LAZY_BIND_F)

            if type(ret) == int or type(ret) == long:

                self.call(ret, args=[], continue_at='ret_from_msgSend', cc=None)

                # self.jump(ret)
                # f = Func(ret, MachO.pd.macho, MachO.pd.task, state)
                # f.analyze()
                # return claripy.BVS("RetFrom_" + hex(addr), 64, uninitialized=True)

            # elif type(ret) == str:
                # return claripy.BVS(ret, 64, uninitialized=True)
            else:
                return ret

    def ret_from_msgSend(self):
        print 'I just jumped to a meth_imp and returned'

    def resolve_invoke(self, state, type=None):

        src_state = state.history.parent.parent
        addr = src_state.addr + src_state.recent_instruction_count * 4
        symbol = MachO.pd.stubs[state.history.parent.addr]

        if type == LAZY_BIND_F:
            MachO.pd.task.cg.insert_invoke(addr, symbol, state, args=resolve_args(state, symbol=symbol))
            if symbol.name in dispatch:
                base = state.regs.x1
                for i in range(1, 6):
                    ea = state.mem[base + 8 * i].long.concrete
                    if ea in MachO.pd.macho.lc_function_starts:
                        return ea
            return claripy.BVS("RetFrom_" + hex(addr), 64, uninitialized=True)
        elif type == MSGSEND:
            receiver = resolve_reg(state, state.regs.x0)
            selector = resolve_reg(state, state.regs.x1)

            if 'instance' in receiver:
                receiver = receiver.split('_')[0]
                meth_type = '-'
            elif '@' in receiver:
                receiver = receiver.split('@')[-1].strip('"')
                meth_type = '-'
            elif 'RetFrom' in receiver:
                meth_type = '-'
            else:
                meth_type = '+'

            description = "{}[{} {}]".format(meth_type, receiver, selector)
            args = resolve_args(state, selector=selector)
            node = MachO.pd.task.cg.insert_invoke(addr, description, state,
                                                  args=args, receiver=receiver, selector=selector)
            if 'tainted' in MachO.pd.task.cg.g.nodes[node]:
                tainted = MachO.pd.task.cg.g.nodes[node]['tainted']
            else:
                tainted = False
            receiver = MachO.pd.task.cg.resolve_receiver(state, node)
            if receiver in OCClass.classes_indexed_by_name:
                description = "{}[{} {}]".format(meth_type, receiver, selector)

            imp = retrieve_f(name=description)['imp']
            if imp:
                return imp
                # return addr
            else:
                ret = claripy.BVS("RetFrom_" + hex(addr), 64, uninitialized=True)
                ret.__setattr__('tainted', tainted)
                return ret


