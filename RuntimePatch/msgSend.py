__author__ = 'gjy'

from Utils import *
from BinaryPatch.Utils import *
from callbacks.delegate import Delegate


class msgSend:

    def __init__(self, state, receiver=None, selector=None, args=None):
        self.state = state
        self.receiver = receiver
        self.selector = selector
        self.args = args
        self.src_state = None
        self.addr = None
        self.description = None
        self.methtype = None
        self.g = MachO.pd.task.cg.g
        self.cg = MachO.pd.task.cg
        self.node = None

    def resolve(self):
        state = self.state
        self.src_state = state.history.parent.parent  # invoke_context_state -> msgSend_stub -> stub_helper
        self.addr = self.src_state.addr + self.src_state.recent_instruction_count * 4  # instruction 4 bytes aligned

        receiver = self.receiver = resolve_reg(state, state.regs.x0)
        selector = self.selector = resolve_reg(state, state.regs.x1)
        args = self.args = resolve_args(state, selector=selector)

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
        self.methtype = meth_type
        self.description = "{}[{} {}]".format(meth_type, receiver, selector)

    def record(self):
        self.node = MachO.pd.task.cg.insert_invoke(self.addr, self.description, self.state,
                                              args=self.args, receiver=self.receiver, selector=self.selector)

    def resolve_in_context(self):
        self.resolve()
        self.record()
        receiver = resolve_receiver(self.cg, self.state, self.node)
        print hex(self.g.nodes[self.node]['addr']), self.g.nodes[self.node]['dp']
        if receiver in OCClass.classes_indexed_by_name:
            self.description = "{}[{} {}]".format(self.methtype, receiver, self.selector)

        delegate = Delegate(self)
        if delegate.isDelegateAccessor():
            print "Find delegate"

        imp = retrieve_f(name=self.description)['imp']
        if imp:
            return imp
        else:
            ret = claripy.BVS("RetFrom_" + hex(self.addr), 64, uninitialized=True)
            # ret.__setattr__('tainted', tainted)
            return ret

    def tainted(self):
        if 'tainted' in self.g.nodes[self.node]:
            tainted = MachO.pd.task.cg.g.nodes[self.node]['tainted']
        else:
            tainted = False
        return tainted



