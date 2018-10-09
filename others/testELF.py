import angr
from graphviz import Digraph


class basicblock:
    bbs = dict()

    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.targets = []

    def add(self, t):
        if self.start not in basicblock.bbs:
            basicblock.bbs[self.start] = self
        if t not in basicblock.bbs[self.start].targets:
            basicblock.bbs[self.start].targets.append(t)

    @staticmethod
    def visualize():
        g = Digraph()
        # first_block = basicblock.bbs[min(basicblock.bbs.keys())]
        for addr in basicblock.bbs.keys():
            g.node(hex(addr), label=hex(addr))
        for b in basicblock.bbs.values():
            for n in b.targets:
                g.edge(hex(b.start), hex(n), label="jmp at {}".format(hex(b.end)))

        g.render('test.gv', view=True)


class analyzer:

    def __init__(self, binary):
        self.p = angr.Project(binary)
        self.mapped_base = self.p.loader.main_object.mapped_base
        self.results = []

    def run(self, start_addr):
        st = self.p.factory.blank_state()
        st.regs.ip = start_addr + self.mapped_base
        sm = self.p.factory.simgr(st)
        st.inspect.b('exit', when=angr.BP_BEFORE, action=self.branch)
        while sm.active:
            # print sm.active[0]
            sm.step()

    def branch(self, state):
        # print "ip:", state.ip,
        # print 'target', hex(state.solver.eval(state.inspect.exit_target)),
        # print 'guard', state.inspect.exit_guard,
        # print 'jumpkind', state.inspect.exit_jumpkind
        if state.inspect.exit_jumpkind == 'Ijk_Call':
            print "method call from {} to {}, skip.".format(state.ip, hex(state.solver.eval(state.inspect.exit_target)))
            # state.inspect.exit_guard = state.solver.BVV(0, 64)
            state.inspect.exit_target = state.regs.lr
        if state.inspect.exit_jumpkind == "Ijk_Boring":
            analyzer.loop_filter(state)
            start = analyzer.state_complete(state)
            end = state.solver.eval(state.ip)
            basicblock(start, end).add(state.solver.eval(state.inspect.exit_target))
            # print "branch from {} to {}".format(hex(start). hex(state.inspect.exit_target)))
        if state.inspect.exit_jumpkind == "Ijk_Ret":
            # print "Function terminated at {}, return {}".format(state.ip, state.regs.r0)
            self.results.append(state.regs.r0)

    @staticmethod
    def state_complete(state):
        history = state.history
        if history.parent.depth:
            while history.parent.jumpkind == 'Ijk_Call':
                history = history.parent
        return state.solver.eval(history.addr)

    @staticmethod
    def loop_filter(state):
        history = state.history
        jmp_target = state.solver.eval(state.inspect.exit_target)
        while history.depth:
            state_addr = history.addr
            if jmp_target == state_addr:
                # print "Loop at {}".format(jmp_target)
                state.inspect.exit_guard = state.solver.BVV(0, 64)
                break
            history = history.parent

    def print_results(self):
        print "Return-value Sets:"
        for r in self.results:
            print r

task = analyzer('/home/gjy/Desktop/MachOA/samples/anagram')
task.run(0xAC8)
task.print_results()

basicblock.visualize()