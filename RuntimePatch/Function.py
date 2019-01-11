from Data.CONSTANTS import *
from Data.data import Data
from Utils import *

from BinaryPatch.Utils import *
from SecCheck.sensitiveData import SensitiveData

import random


class Func:

    def __init__(self, addr, binary, task, state, args=None):

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
        self.ret = []
        self.ret_type = None

    def init(self):
        if self.start_ea not in OCFunction.meth_list:
            print 'NOT A FUNCTION START EA.'
            return None
        elif self.start_ea in OCFunction.oc_function_set:
            f = self._oc_function = OCFunction.oc_function_set[self.start_ea]
            self.ret_type = f.ret_type
            self.name = f.expr
            self._oc_class = OCClass.classes_indexed_by_name[self._oc_function.receiver]

            if self._oc_function.meth_type == '-':
                receiver = FORMAT_INSTANCE.format(data_type=str_to_type(f.receiver), ptr=hex(f.imp), instance_type='REC',
                                                  name='{}#{}'.format(f.receiver, random.randint(0, IRR)))
                x0 = self.init_state.solver.BVS(receiver, 64)
            elif f.meth_type == '+':
                x0 = self.init_state.solver.BVV(OCClass.classes_indexed_by_name[f.receiver].class_addr, 64)
            self.init_state.regs.x0 = x0

            args_data = []
            if self.args:
                args = self.args
            elif OCFunction.find_detailed_prototype(f.selector, self._oc_class):
                args = OCFunction.find_detailed_prototype(f.selector, self._oc_class)[1:]
            for i in range(0, f.selector.count(':')):
                if args:
                    reg = FORMAT_INSTANCE.format(data_type=args[i], ptr=hex(f.imp), instance_type='PARA',
                                                 name='{}#{}'.format(type_to_str(args[i]), random.randint(0, IRR)))
                else:
                    reg = FORMAT_INSTANCE.format(data_type='unknown', ptr=hex(f.imp), instance_type='PARA', name="P" + str(i))
                self.init_state.registers.store('x{}'.format(str(i+2)), self.init_state.solver.BVS(reg, 64))
                args_data.append(Data(self.init_state, reg=self.init_state.registers.load('x{}'.format(str(i+2)))))

            self.task.cg.add_start_node(self.start_ea, 'Start', self.init_state, args=args_data)
            return self
        else:
            # subroutine
            self.name = OCFunction.meth_data[self.start_ea]['name']
            self.task.cg.add_start_node(self.start_ea, 'Start', self.init_state)
            return self

    def analyze(self):
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
        if len(self.task.cg.g.nodes) > 100:
            self.active = False
            self.task.logger.write('{} {}\n'.format(hex(self.start_ea), self.name))

    def check_if_as_ret(self, state):
        """
        If the simulate manager has no successors, you have to decide whether the marked data used as ret value.
        Because the last instruction of function may be 'RET' or symbol call, take care.
        Because of Inter-procedural analysis, so we need to resolve the context.
        :return:
        """
        reg_data = Data(state, reg=state.regs.get('x0'))
        if 'Marked' in reg_data.expr:
            self.ret = resolve_context(state.addr)

    def get_ret_values(self):
        if 'v' not in self.ret_type:
            return self.ret

    def sensitive(self, state):
        """
        Check the necessity to continue this state.
        :return:
        """
        # msg invoke
        if state.addr > self.text_seg_boundary:
            return True

        # You have to consider inter-procedural invokes.
        conetxt_func_ea = resolve_context(state.addr)
        if conetxt_func_ea in SensitiveData.ssData.as_ret_value:
            for end in SensitiveData.ssData.as_ret_value[conetxt_func_ea]['sel']:
                if state.addr < end:
                    return True

        # Check no sensitive data in this state.
        ea = state.regs.bp
        while state.solver.eval(ea > state.regs.sp):
            if 'Marked' in Data(state, reg=ea).expr:
                print 'Sensitive data {} exists at {}, state:{}'.format(Data(state, reg=ea).expr, ea, hex(state.addr))
                return True
            ea -= 8

        for i in range(0, 32):
            reg_data = Data(state, reg=state.regs.get('x{}'.format(i)))
            if 'Marked' in reg_data.expr:
                print 'Sensitive data X{} {} exists at {}, state:{}'.format(i, reg_data.expr, hex(state.addr), hex(state.addr))
                return True
            if SensitiveData.ssData.selector in reg_data.expr:
                print 'Selector {} occurs at {}'.format(reg_data.expr, hex(state.addr))
                return True
        return False

    def not_sensitive(self, state):
        return not self.sensitive(state)

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
