#coding=utf-8
__author__ = 'gjy'

from Data.CONSTANTS import *
from Data.data import Data, SEL, Receiver
from BinaryPatch.Utils import *
from Data.MachO import *
from RuntimePatch.Utils import expr_args
from SecCheck.analyzer import Analyzer


class Message:
    def __init__(self, state, ea, receiver=None, selector=None, args=None, simprocedure_handler=None, send_super=False):
        self.simprocedure_handler = simprocedure_handler
        self.dispatch_state = state
        self.receiver = receiver
        self.selector = selector
        self.args = args
        self.send_super = send_super
        self.invoke_ea = ea
        self.description = None
        self.g = MachO.pd.task.cg.g
        self.cg = MachO.pd.task.cg
        self.node = None

    def dynamic_bind(self):
        self.selector = SEL(
            Data(self.dispatch_state, reg=self.dispatch_state.regs.x1)).rearrange_if_necessary()  # take care of 'performSelector'
        self.receiver = Receiver(Data(self.dispatch_state, reg=self.dispatch_state.regs.x0),
                                 self.selector)
        # 根据selector来推断receiver类型这个方法，考虑到误报时后果严重，因此保守起见暂时禁止。
        # if not self.receiver.oc_class:
        #     self.receiver.type_infer_by_selector()
        self.description = "{}[{} {}]".format(self.receiver.type, self.receiver.expr, self.selector.expr)

        # 如果是performSelector等方法，返回的imp应该为即将进入的代码imp。
        msg_handler = OCFunction.ask_for_imp_at_runtime(rec=self.receiver, sel=self.selector, send_super=self.send_super)
        return msg_handler

    def send(self):

        # 动态绑定，需要完成查找imp的过程；在查找过程中如有必要，对receiver的类型进行确认。
        imp = self.dynamic_bind()

        self.node = MachO.pd.task.cg.insert_invoke(self.invoke_ea, self.description,
                                                   self.dispatch_state,
                                                   receiver=self.receiver.data.expr,
                                                   selector=self.selector.expr,
                                                   args=self.selector.args)

        if imp:
            # 开过程间分析需要注意一点：不需要推测返回值，因为进入过程后返回值自然产生。
            # 即使进行过程间分析，还可能会有两种类型的限制，一是数据敏感；二是控制流敏感（预定义了函数调用链）
            if SDA:
                if Analyzer.sensitive_API(msg=self):
                    self.prepare_for_new_context()
                    # self.simprocedure_handler.call(sel_imp, args=[], continue_at='ret_from_msgSend', cc=None)
                    self.simprocedure_handler.jump(imp)
                    return
            if CS_LIMITED:
                if Analyzer.allowed_step_in(self, imp):
                    self.prepare_for_new_context()
                    self.simprocedure_handler.jump(imp)
                    return

            # 如果经过限制，没有必要进行过程间分析，依然会来到接下来的返回值推断。

        # 推测返回值。实际上，当不进行过程间分析时，这里是模拟调用对程序状态的影响
        ret_type = 'unknown'
        if self.receiver.oc_class:
            ret_type = OCFunction.find_detailed_prototype(self.selector.expr, self.receiver.oc_class)[0]
        if SDA:
            # 注意，这里的前提是不进行过程间分析，因此在进行污点分析时要考虑是否保守
            # 当receiver，或者参数存在被标记时，默认返回值被标记.field-insensitive
            # 当调用为敏感API或者推测的返回值类型为敏感ADT时，返回值需要标记。
            if Analyzer.msg_tainted(self) or Analyzer.sensitive_API(msg=self) or Analyzer.sensitive_ADT(ret_type):
                if 'Marked' not in ret_type:
                    ret_type = 'Marked_{}'.format(ret_type)

        x0 = FORMAT_INSTANCE.format(data_type=ret_type, instance_type='RET', ptr=hex(self.invoke_ea),
                                    name="[{} {}]".format(self.receiver.expr, self.selector.expr))
        self.g.nodes[self.node]['ret'] = x0
        self.dispatch_state.regs.x0 = self.dispatch_state.solver.BVS(x0, 64)
        self.check_particularity()

    def send2(self):

        # 动态绑定，确定receiver和selector，需要完成查找imp的过程。
        imp = self.dynamic_bind()

        # 推测返回值，根据已解析的receiver和selector推测返回值。实际上，当不进行过程间分析时，这里是模拟调用对程序状态的影响。
        ret_type = 'unknown'
        if self.receiver.oc_class:
            ret_type = OCFunction.find_detailed_prototype(self.selector.expr, self.receiver.oc_class)[0]
            if ret_type == 'instancetype':
                ret_type = self.receiver.oc_class.name

        x0 = FORMAT_INSTANCE.format(data_type=ret_type, instance_type='RET', ptr=hex(self.invoke_ea),
                                    name="[{} {}]".format(self.receiver.expr, self.selector.expr))

        self.dispatch_state.regs.x0 = self.dispatch_state.solver.BVS(x0, 64)
        self.check_particularity()
        self.node = MachO.pd.task.cg.insert_invoke(self.invoke_ea, self.description,
                                                   self.dispatch_state,
                                                   receiver=self.receiver.data.expr,
                                                   selector=self.selector.expr,
                                                   args=self.selector.args)
        self.g.nodes[self.node]['ret'] = x0
        self.g.nodes[self.node]['ret_type'] = ret_type
        self.g.nodes[self.node]['rec_type'] = self.receiver.data_type
        self.g.nodes[self.node]['rec_dpr'] = self.receiver.dpr
        self.g.nodes[self.node]['handler'] = imp

    def tainted(self):
        if 'tainted' in self.g.nodes[self.node]:
            tainted = MachO.pd.task.cg.g.nodes[self.node]['tainted']
        else:
            tainted = False
        return tainted

    def check_particularity(self):
        if self.selector.expr == 'getCString:maxLength:encoding:':
            self.dispatch_state.memory.store(self.dispatch_state.regs.x2, self.dispatch_state.regs.x0)

    def prepare_for_new_context(self):
        if self.selector.expr == 'performSelector:withObject:afterDelay:':
            # 原本的第一个参数作为selector,原本withObject:对应的参数作为第一个参数
            self.dispatch_state.registers.store('x1', self.dispatch_state.regs.x2.ast)
            self.dispatch_state.registers.store('x2', self.dispatch_state.regs.x3.ast)
