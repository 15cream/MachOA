from Data.CONSTANTS import *
from RuntimePatch.DependencyResolve import *


class TaintAnalyzer():

    def __init__(self):
        pass

    def run(self, state, graph, node):
        receiver = graph.nodes[node]['args'][0]
        selector = graph.nodes[node]['args'][1]

        if receiver in RECEIVERS or selector in SELECTORS or self.has_tainted_vals(state, node):
            resolve_dp(node)
            self.taint(state, node)
            print 'SINK: ', graph.nodes[node]['dp']

    def has_tainted_vals(self, state, node):
        count = len(self.g.nodes[node]['args'])
        for i in range(0, count):
            if 'tainted' in state.regs.get("x{}".format(i)).ast.__dict__:
                if state.regs.get("x{}".format(i)).ast.tainted:
                    return True
        return False

    def taint(self, state, node):
        count = len(self.g.nodes[node]['args'])
        for i in range(0, count):
            state.regs.get("x{}".format(i)).ast.__setattr__('tainted', True)
        self.g.nodes[node]['tainted'] = True