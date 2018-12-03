from Data.OCFunction import OCFunction


class Func:

    def __init__(self, addr, binary, task, state, args=None):
        self.addr = addr
        # self.next_func_addr = binary.lc_function_starts[binary.lc_function_starts.index(addr) + 1]
        self.name = OCFunction.meth_data[addr]['name']
        self.binary = binary
        self.task = task
        self.init_state = state
        self.active = True
        task.cg.add_start_node(addr, 'Start', self.init_state)
        self.init_regs(args)

    def init_regs(self, args):
        if self.addr in OCFunction.meth_data:
            meth_data = OCFunction.meth_data[self.addr]
            class_data = meth_data['class']
            if class_data:
                if self.addr in class_data.instance_meths:
                    self.init_state.regs.x0 = self.init_state.solver.BVS(class_data.name + "_instance", 64)
                else:
                    self.init_state.regs.x0 = self.init_state.solver.BVV(class_data.classref_addr, 64)

                for i in range(0, meth_data['name'].count(':')):
                    init_reg_val = args[i+1] if args else "P" + str(i)
                    self.init_state.registers.store('x{}'.format(str(i+2)), self.init_state.solver.BVS(init_reg_val, 64))
        else:
            pass  # subroutine

    def analyze(self):
        print 'ANALYZE {} {}'.format(hex(self.addr), self.name)
        if self.addr in OCFunction.meth_list:
            self.init_state.regs.ip = self.addr
            simgr = self.task.p.factory.simgr(self.init_state)
            while simgr.active and self.active:
                simgr.step()
                # self.check_status()

    def check_status(self):
        if len(self.task.cg.g.nodes) > 100:
            self.active = False
            self.task.logger.write('{} {}\n'.format(hex(self.addr), self.name))
