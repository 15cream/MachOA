import angr
import claripy
from RuntimePatch.ExitProtect import *
from RuntimePatch.AddressConcretize import *
from RuntimePatch.mem_read import *


class Slice:

    def __init__(self, task, state, start=None, end=None):
        self.init_state = state  # add_options = {"SYMBOLIC_WRITE_ADDRESSES"}
        self.task = task
        self.binary = task.macho

        self.start_ea = start
        self.end_ea = end

        # if start_ea is the function start, initial the state

        # else check code or not.

        self.code_segment = MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text')
        task.cg.add_start_node(self.start_ea, 'Start', self.init_state)

    def run(self):
        self.init_state.regs.ip = self.start_ea
        simgr = self.task.p.factory.simgr(self.init_state)
        while simgr.active:
            simgr.step()
            simgr.move(from_stash='active', to_stash='terminated',
                       filter_func=self.terminate)

    def terminate(self, s):
        ip = s.solver.eval(s.addr)
        if ip > self.code_segment.max_addr:
            return False
        elif ip > self.end_ea:
            return True
        return False

    def static_analysis(self):
        irsb = self.task.p.factory.block(self.start_ea).vex
        for stmt in irsb.statements:
            stmt.pp()

    def pointer_analysis(self):
        self.init_state.regs.ip = self.start_ea + 4
        self.init_state.regs.x8 = claripy.BVS('Watched_Pointer', 64)
        simgr = self.task.p.factory.simgr(self.init_state)
        while simgr.active:
            simgr.step()

    def clean(self, state):
        try:
            return b'Watched_Pointer' in state.posix.dumps(1)
        except Exception as e:
            return False