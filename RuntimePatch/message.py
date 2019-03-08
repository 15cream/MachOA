__author__ = 'gjy'

from Data.CONSTANTS import *
from Data.data import Data, SEL, Receiver
from BinaryPatch.Utils import *
from RuntimePatch.Utils import expr_args
from SecCheck.SinkAnalyzer import SinkAnalyzer
from callbacks.delegate import Delegate


class Message:
    def __init__(self, state, receiver=None, selector=None, args=None, simprocedure_handler=None, send_super=False):
        self.simprocedure_handler = simprocedure_handler
        self.dispatch_state = state
        self.receiver = receiver
        self.selector = selector
        self.args = args
        self.send_super = send_super
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
            sel_imp = OCFunction.ask_for_imp(rec=self.receiver.oc_class, sel=self.selector, send_super=self.send_super)
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
        Used for sensitive database analysis.
        1. dynamic_bind
        2. check if sensitive database used as parameter, True: go into the function. False: record and go on.
        :return:
        """
        self.dynamic_bind()

        # Infer ret_type and mark it if sensitive.
        ret_type = 'unknown'
        if self.receiver.oc_class:
            ret_type = OCFunction.find_detailed_prototype(self.selector.expr, self.receiver.oc_class)[0]

        if SDA:
            # Sink check.

            sink_analyzer = SinkAnalyzer.singleton
            if sink_analyzer.sensitive_data_returned(self) and 'Marked_' not in ret_type:
                ret_type = 'Marked_{}'.format(ret_type)

            # field-insensitive
            if sink_analyzer.sensitive_data_as_receiver(self) and 'Marked_' not in ret_type:
                ret_type = 'Marked_{}'.format(ret_type)

            if sink_analyzer.sensitive_data_as_parameter(self):
                print "* Sensitive database {} used as parameter. *  {} {}".format(
                    expr_args(self.selector.args), hex(self.invoke_ea), self.description)
                if sink_analyzer.receiver_tainted(self) and 'Marked_' not in self.receiver.expr:
                    self.receiver.data.mark()
                    ret_type = 'Marked_{}'.format(ret_type)

        if IPC:
            if not self.receiver.oc_class:
                self.receiver.type_infer_by_selector()
            sel_imp = OCFunction.ask_for_imp(rec=self.receiver.oc_class, sel=self.selector, send_super=self.send_super)
            if sel_imp:
                # SETTER OR NOT
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
        self.check_particularity()
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

    def check_particularity(self):
        if self.selector.expr == 'getCString:maxLength:encoding:':
            self.dispatch_state.memory.store(self.dispatch_state.regs.x2, self.dispatch_state.regs.x0)
            print ''
