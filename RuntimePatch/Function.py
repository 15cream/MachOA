#coding=utf-8
from Data.CONSTANTS import *
from Data.data import Data
from Utils import *

from BinaryPatch.Utils import *
from SecCheck.sensitiveData import SensitiveData
from RuntimePatch.Utils import resolve_context
from RuntimePatch.ExecutionLimitation import CLimitation

import random


class Func:

    def __init__(self, addr, binary, task, state, args=None, limits=None):

        self.start_ea = addr
        self.binary = binary
        self.task = task
        self.init_state = state
        self.init_state.globals['start_func_object'] = self
        self.active = True
        self.args = args
        self._oc_function = None
        self._oc_class = None
        self.name = None
        self.text_seg_boundary = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text').max_addr
        self.ret = set()
        self.ret_type = None
        self.execution_limitations = limits

    def init(self):
        if self.start_ea not in OCFunction.meth_data:
            print 'NOT A FUNCTION START EA.'
            return None
        elif self.start_ea in OCFunction.oc_function_set:
            f = self._oc_function = OCFunction.oc_function_set[self.start_ea]
            self.ret_type = f.ret_type
            self.name = f.expr
            self._oc_class = OCClass.retrieve_by_classname(self._oc_function.receiver, is_superclass=False)

            if self._oc_function.meth_type == '-':
                receiver = FORMAT_INSTANCE.format(data_type=str_to_type(f.receiver), ptr=hex(f.imp), instance_type='REC',
                                                  name='{}#{}'.format(f.receiver, random.randint(0, IRR)))
                x0 = self.init_state.solver.BVS(receiver, 64)
            elif f.meth_type == '+':
                x0 = self.init_state.solver.BVV(
                    OCClass.retrieve_by_classname(f.receiver, is_superclass=False).class_addr, 64)
            self.init_state.regs.x0 = x0

            args_data = []
            if self.args:
                args = self.args
            elif OCFunction.find_detailed_prototype(f.selector, self._oc_class):
                args = OCFunction.find_detailed_prototype(f.selector, self._oc_class)[1:]
            for i in range(0, f.selector.count(':')):
                if args:
                    reg = FORMAT_INSTANCE.format(data_type=args[i], ptr=hex(f.imp), instance_type='GEN_PARA',
                                                 name='{}#P{}_{}'.format(type_to_str(args[i]), i, random.randint(0, IRR)))
                else:
                    reg = FORMAT_INSTANCE.format(data_type='unknown', ptr=hex(f.imp), instance_type='GEN_PARA', name="P" + str(i))
                self.init_state.registers.store('x{}'.format(str(i+2)), self.init_state.solver.BVS(reg, 64))
                args_data.append(Data(self.init_state, bv=self.init_state.registers.load('x{}'.format(str(i + 2)))))

            self.task.cg.add_start_node(self.start_ea, 'Start', self.init_state, args=args_data)
            return self
        else:
            # subroutine
            self.name = OCFunction.meth_data[self.start_ea]['name']
            self.task.cg.add_start_node(self.start_ea, 'Start', self.init_state)
            return self

    def analyze(self):
        self.init_state.regs.ip = self.start_ea
        self.init_state.globals['Func_Object'] = self
        self.init_state.globals['sensitive_data'] = dict()
        simgr = self.task.p.factory.simgr(self.init_state)
        while simgr.active:
            simgr.step()
            filter = None
            if self.execution_limitations:
                filter = self.state_filter
            if CS_LIMITED:
                filter = CLimitation.filter
            if filter:
                simgr.move(from_stash='active', to_stash='useless', filter_func=filter)

    def state_filter(self, state):
        """
        :param state:
        :return: 如果当前state没有必要再继续，返回 True。
        """
        if state.addr > self.text_seg_boundary:
            return False

        ctx = resolve_context(state.addr)
        if ctx in self.execution_limitations:
            # 在过程内对state进行限制
            limits = self.execution_limitations[ctx]
            if state.addr == ctx or state.addr in limits['paths']:
                return False
            if state.addr in limits['sensitive_blocks']:
                if limits['target'] in OCFunction.oc_function_set:
                    # 标记要检查什么数据
                    state.globals['sensitive_data'][ctx] = OCFunction.oc_function_set[limits['target']].selector
                else:
                    pass  # 默认subroutine只出现在一个block里，当前这个block允许就够了
                return False
            if ctx in state.globals['sensitive_data']:  # 表明在到达这个状态的过程中曾经出现过selector
                if self.is_data_in_state(state, state.globals['sensitive_data'][ctx]):
                    return False
                else:
                    del state.globals['sensitive_data'][ctx]   # 如果被标记的数据不在了，就可以终止了
                    return True
            return True

    def check_if_as_ret(self, state):
        """
        If the simulate manager has no successors, you have to decide whether the marked database used as ret value.
        Because the last instruction of function may be 'RET' or symbol call, take care.
        Because of Inter-procedural analysis, so we need to resolve the context.
        :return:
        """
        reg_data = Data(state, bv=state.regs.get('x0'))
        if 'Marked' in reg_data.expr:
            self.ret = resolve_context(state.addr)

    def get_ret_values(self):
        if self.ret_type and 'v' not in self.ret_type:  # subroutine may have no ret_type
            return self.ret

    @staticmethod
    def check_ret(state):
        func_ctx = resolve_context(state.addr)
        # if state.addr == func_ctx
        if func_ctx in OCFunction.oc_function_set:
            f = OCFunction.oc_function_set[func_ctx]
            if 'v' not in f.ret_type:  # has ret value
                pass
            else:
                return None

    def sensitive_analyze(self):
        print 'ANALYZE {} {}'.format(hex(self.start_ea), self.name)
        self.init_state.regs.ip = self.start_ea
        simgr = self.task.p.factory.simgr(self.init_state)
        while self.active:
            simgr.step()
            if SDA:
                simgr.move(from_stash='active', to_stash='clean', filter_func=self.not_sensitive)
            if not simgr.active:
                self.active = False

    def check_status(self):
        if len(self.task.cg.g.nodes) > 160:
            self.active = False
            self.task.logger.write('{} {}\n'.format(hex(self.start_ea), self.name))

    def sensitive(self, state):
        """
        Check the necessity to continue this state.
        :return:
        """
        # msg invoke
        if state.addr > self.text_seg_boundary:
            return True

        # You have to consider inter-procedural invokes.
        # TODO
        context = resolve_context(state.addr)
        # for api in SinkAnalyzer.sensitive_APIs:
        #     if state.addr < api.find_selector_last_occurs(context):
        #         return True

        # Check no sensitive database in this state.
        ea = state.regs.bp
        while state.solver.eval(ea > state.regs.sp):
            if 'Marked' in Data(state, bv=ea).expr:
                print 'Sensitive database {} exists at {}, state:{}'.format(Data(state, bv=ea).expr, ea, hex(state.addr))
                return True
            ea -= 8

        for i in range(0, 32):
            reg_data = Data(state, bv=state.regs.get('x{}'.format(i)))
            if 'Marked' in reg_data.expr:
                print 'Sensitive database X{} {} exists at {}, state:{}'.format(i, reg_data.expr, hex(state.addr), hex(state.addr))
                return True
            if SensitiveData.ssData.selector in reg_data.expr:
                print 'Selector {} occurs at {}'.format(reg_data.expr, hex(state.addr))
                return True
        return False

    def not_sensitive(self, state):
        return not self.sensitive(state)

    def is_data_in_state(self, state, data):
        # if state.addr > self.text_seg_boundary:
        #     return True
        ea = state.regs.bp
        while state.solver.eval(ea > state.regs.sp):
            if data in Data(state, bv=ea).expr:
                return True
            ea -= 8

        for i in range(0, 30):
            reg_data = Data(state, bv=state.regs.get('x{}'.format(i)))
            if data in reg_data.expr:
                return True

        return False


