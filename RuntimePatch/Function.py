from Data.OCFunction import OCFunction


class Func:

    def __init__(self, addr, binary, task, state):
        self.addr = addr
        self.next_func_addr = binary.lc_function_starts[binary.lc_function_starts.index(addr) + 1]
        self.name = OCFunction.meth_data[addr]['name']
        self.binary = binary
        self.task = task
        self.init_state = state
        task.cg.add_start_node(addr, 'Start', self.init_state)

    def init_regs(self):
        if self.addr in OCFunction.meth_data:  # or could be subroutine
            meth_data = OCFunction.meth_data[self.addr]
            class_data = meth_data['class']
            if class_data:
                if self.addr in class_data.instance_meths:
                    self.init_state.regs.x0 = self.init_state.solver.BVS(class_data.name + "_instance", 64)
                else:
                    self.init_state.regs.x0 = self.init_state.solver.BVV(class_data.classref_addr, 64)
                argc = meth_data['name'].count(':')
                for i in range(0, argc):
                    reg = 'x' + str(i + 2)
                    newval = self.init_state.solver.BVS("P" + str(i), 64)
                    self.init_state.registers.store(reg, newval)

    def analyze(self):
        if self.addr in OCFunction.meth_list:
            self.init_state.regs.ip = self.addr
            simgr = self.task.p.factory.simgr(self.init_state)
            while simgr.active:
                simgr.step()