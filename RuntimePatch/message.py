__author__ = 'gjy'

from Data.CONSTANTS import *
from Data.data import Data, SEL, Receiver
from BinaryPatch.Utils import *
from RuntimePatch.Utils import expr_args
from SecCheck.SinkAnalyzer import SinkAnalyzer
from SecCheck.sensitiveData import SensitiveData
from callbacks.delegate import Delegate


class Message:
    def __init__(self, state, receiver=None, selector=None, args=None, simprocedure_handler=None):
        self.simprocedure_handler = simprocedure_handler
        self.dispatch_state = state
        self.receiver = receiver
        self.selector = selector
        self.args = args
        self.invoke_state = state.history.parent.parent  # invoke_context_state -> msgSend_stub -> stub_helper
        self.invoke_ea = self.invoke_state.addr + self.invoke_state.recent_instruction_count * 4
        self.description = None
        self.g = MachO.pd.task.cg.g
        self.cg = MachO.pd.task.cg
        self.node = None

    def dynamic_bind(self):
        self.selector = SEL(
            Data(self.dispatch_state, reg=self.dispatch_state.regs.x1))  # take care of 'performSelector'
        self.receiver = Receiver(Data(self.dispatch_state, reg=self.dispatch_state.regs.x0),
                                 self.selector)
        self.description = "{}[{} {}]".format(self.receiver.type, self.receiver.expr, self.selector.expr)

    def send(self):
        self.dynamic_bind()
        # if 'msgQueue' in self.dispatch_state.regs.x0.ast.__dict__:
        # self.dispatch_state.regs.x0.ast.__dict__['msgQueue'].append(self)
        # else:
        # self.dispatch_state.regs.x0.ast.__dict__['msgQueue'] = [self, ]

        # If do the inter-procedure analysis, there's no need to think about ret_val.
        # But if we just do inner-procedure analysis, how to express that a message has been send?
        if IPC:
            # sel_imp = retrieve_f(name=self.description)['imp']
            sel_imp = OCFunction.ask_for_imp(rec=self.receiver.oc_class, sel=self.selector)
            if sel_imp:
                # Record a start node here.
                self.node = MachO.pd.task.cg.insert_invoke(self.invoke_ea, self.description, self.dispatch_state,
                                                           receiver=self.receiver.data.expr,
                                                           selector=self.selector.expr,
                                                           args=self.selector.args)
                # self.cg.add_start_node(sel_imp, 'Start', self.dispatch_state, args=self.selector.args, edge=True)
                # self.simprocedure_handler.call(sel_imp, args=[], continue_at='ret_from_msgSend', cc=None)
                self.simprocedure_handler.jump(sel_imp)
                return

        # '({data_type}<{instance_type}:{ptr}>){name}'
        # Pay attention. Because invokes are path sensitive, look for your ret_val in your history path.
        ret_type = 'unknown'
        if self.receiver.oc_class:
            ret_type = OCFunction.find_detailed_prototype(self.selector.expr, self.receiver.oc_class)[0]

        x0 = FORMAT_INSTANCE.format(data_type=ret_type, instance_type='RET', ptr=hex(self.invoke_ea),
                                    name="[{} {}]".format(self.receiver.expr, self.selector.expr))
        self.dispatch_state.regs.x0 = self.dispatch_state.solver.BVS(x0, 64)

        self.node = MachO.pd.task.cg.insert_invoke(self.invoke_ea, self.description, self.dispatch_state,
                                                   receiver=self.receiver.data.expr,
                                                   selector=self.selector.expr,
                                                   args=self.selector.args)

    def returned(self):
        print '?'

    def send2(self):
        """
        Used for sensitive data analysis.
        1. dynamic_bind
        2. check if sensitive data used as parameter, True: go into the function. False: record and go on.
        :return:
        """
        self.dynamic_bind()

        # Infer ret_type and mark it if sensitive.
        ret_type = 'unknown'
        if self.receiver.oc_class:
            ret_type = OCFunction.find_detailed_prototype(self.selector.expr, self.receiver.oc_class)[0]

        if SDA:
            # Sink check.
            sink_analyzer = SinkAnalyzer(self)
            if sink_analyzer.sensitive_data_as_receiver() and 'Marked_' not in ret_type:
                ret_type = 'Marked_{}'.format(ret_type)
            if sink_analyzer.sensitive_data_as_parameter():
                print '* Sensitive data {} used as parameter. * {}'.format(expr_args(self.selector.args), self.description)
                if SDA_IPC:
                    sel_imp = OCFunction.ask_for_imp(rec=self.receiver.oc_class, sel=self.selector)
                    if sel_imp:
                        self.node = MachO.pd.task.cg.insert_invoke(self.invoke_ea, self.description,
                                                                   self.dispatch_state,
                                                                   receiver=self.receiver.data.expr,
                                                                   selector=self.selector.expr,
                                                                   args=self.selector.args)
                        self.simprocedure_handler.jump(sel_imp)
                        return

        # Store the ret_value if necessary
        x0 = FORMAT_INSTANCE.format(data_type=ret_type, instance_type='RET', ptr=hex(self.invoke_ea),
                                    name="[{} {}]".format(self.receiver.expr, self.selector.expr))
        self.dispatch_state.regs.x0 = self.dispatch_state.solver.BVS(x0, 64)
        self.node = MachO.pd.task.cg.insert_invoke(self.invoke_ea, self.description, self.dispatch_state,
                                                   receiver=self.receiver.data.expr,
                                                   selector=self.selector.expr,
                                                   args=self.selector.args)

    def tainted(self):
        if 'tainted' in self.g.nodes[self.node]:
            tainted = MachO.pd.task.cg.g.nodes[self.node]['tainted']
        else:
            tainted = False
        return tainted



        # # origin
        # def _resolve_in_context(self):
        # self.send()
        # self.record()
        #     receiver = resolve_receiver(self.cg, self.dispatch_state, self.node)
        #     print hex(self.g.nodes[self.node]['addr']), self.g.nodes[self.node]['dp']
        #     if receiver in OCClass.classes_indexed_by_name:
        #         self.description = "{}[{} {}]".format(self.methtype, receiver, self.selector)
        #
        #     delegate = Delegate(self)
        #     if delegate.isDelegateAccessor():
        #         print "Find delegate"
        #
        #     imp = retrieve_f(name=self.description)['imp']
        #     if imp:
        #         return imp
        #     else:
        #         ret = claripy.BVS("RetFrom_" + hex(self.invoke_ea), 64, uninitialized=True)
        #         # ret.__setattr__('tainted', tainted)
        #         return ret


# for i in range(0, 32):
# reg = self.dispatch_state.regs.get('x{}'.format(i))
# if 'msgQueue' in reg.ast.__dict__:
# print 'x{}'.format(i)
#         for msg in reg.ast.__dict__['msgQueue']:
#             print hex(msg.invoke_ea), msg.description

