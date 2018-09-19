import networkx as nx
from Data.binary import MachO
from angr.state_plugins.history import SimStateHistory

class CG:

    def __init__(self):
        self.g = nx.DiGraph()

    def insert_invoke(self, ea, description, state):
        # ea : where the invoke happens
        # description could be function name or symbol name
        node = "context:{}\naddr:{}\ndes:{}".format(hex(MachO.resolve_context(ea)), hex(ea), description)
        if node not in self.g.nodes:
            self.g.add_node(node, des=description, context=MachO.resolve_context(ea))
        else:
            print 'COME TO THIS INVOKE AGAIN. -> {}'.format(hex(ea))
        state.history.invoke_addr = ea
        state.history.node = node
        state.history.constraints = self.repr_constraints(state)
        last_invoke_history = self.find_last_invoke(state)
        color = 'red' if self.g.nodes[last_invoke_history.node]['context'] != self.g.nodes[node]['context'] else 'green'
        self.g.add_edge(last_invoke_history.node, node,
                        label='\n'.join(self.find_constraint_addtion(last_invoke_history, state.history)),
                        color=color)
        print "from {} to {}".format(last_invoke_history.node, node)

    def find_last_invoke(self, state):
        history = state.history.parent
        while history:
            if history.invoke_addr:
                return history
            history = history.parent

    def repr_constraints(self, state):
        cs = []
        if state.solver.constraints:
            for c in state.solver.constraints:
                cs.append(str(c).replace('<', '').replace('>', ''))
        return cs

    def find_constraint_addtion(self, src, des):
        cs = []
        for c in des.constraints:
            if c not in src.constraints:
                cs.append(c)
        return cs

    def view(self):
        nx.drawing.nx_agraph.write_dot(self.g, 'callG.dot')

    def add_simple_node(self, ea, description, state):
        node = "context:{}\naddr:{}\ndes:{}".format(hex(MachO.resolve_context(ea)), hex(ea), description)
        if node not in self.g.nodes:
            self.g.add_node(node, des=description, context=MachO.resolve_context(ea))
            state.history.invoke_addr = ea
            state.history.constraints = []
            state.history.node = node



