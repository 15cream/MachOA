from Data.OCFunction import OCFunction
from Data.OCClass import OCClass
from Data.CONSTANTS import *
from Utils import *

import random


class Func:

    def __init__(self, addr, binary, task, state, args=None):

        self.start_ea = addr
        self.binary = binary
        self.task = task
        self.init_state = state
        self.active = True
        self.args = args
        self._oc_function = None
        self._oc_class = None
        self.name = None
        task.cg.add_start_node(addr, 'Start', self.init_state)

    def init(self):
        if self.start_ea not in OCFunction.meth_list:
            print 'NOT A FUNCTION START EA.'
            return None
        elif self.start_ea in OCFunction.oc_function_set:
            f = self._oc_function = OCFunction.oc_function_set[self.start_ea]
            self.name = f.expr
            self._oc_class = OCClass.classes_indexed_by_name[self._oc_function.receiver]

            if self._oc_function.meth_type == '-':
                receiver = FORMAT_INSTANCE.format(data_type=str_to_type(f.receiver), ptr=hex(f.imp), instance_type='REC',
                                                  name='{}#{}'.format(f.receiver, random.randint(0, IRR)))
                x0 = self.init_state.solver.BVS(receiver, 64)
            elif f.meth_type == '+':
                x0 = self.init_state.solver.BVV(OCClass.classes_indexed_by_name[f.receiver].class_addr, 64)
            self.init_state.regs.x0 = x0

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

            return self
        else:
            # subroutine
            self.name = OCFunction.meth_data[self.start_ea]['name']
            return self

    def analyze(self):
        print 'ANALYZE {} {}'.format(hex(self.start_ea), self.name)
        self.init_state.regs.ip = self.start_ea
        simgr = self.task.p.factory.simgr(self.init_state)
        while simgr.active and self.active:
            simgr.step()
            # self.check_status()

    def check_status(self):
        if len(self.task.cg.g.nodes) > 100:
            self.active = False
            self.task.logger.write('{} {}\n'.format(hex(self.start_ea), self.name))
