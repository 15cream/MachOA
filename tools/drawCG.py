import networkx as nx
from Data.binary import MachO
from Data.function import Function
from Data.CONSTANTS import *
import copy

class CG:

    def __init__(self):
        self.g = nx.DiGraph()
        self.hs = dict()
        self.start = None

    def insert_invoke(self, ea, description, state, args=None):
        # ea : where the invoke happens
        # description could be function name or symbol name
        context = MachO.resolve_context(ea)
        context_name = Function.meth_data[context]['name']
        node = INVOKEFS.format(hex(context), context_name, state.history.depth, hex(ea), description, self.expr_args(args))
        if node not in self.g.nodes:
            self.g.add_node(node, des=description, context=context)
        else:
            print 'COME TO THIS INVOKE AGAIN. -> {}'.format(hex(ea))
        # state.history.invoke_addr = ea
        # state.history.node = node
        # state.history.constraints = self.repr_constraints(state)
        self.hs[state.history] = hs(ea, self.repr_constraints(state), node)
        last_invoke_history = self.find_last_invoke(state)
        color = 'red' if self.g.nodes[last_invoke_history.node]['context'] != self.g.nodes[node]['context'] else 'green'
        self.g.add_edge(last_invoke_history.node, node,
                        # label='\n'.join(self.find_constraint_addtion(state, last_invoke_history, self.hs[state.history])),
                        color=color)
        print "from {} to {}".format(last_invoke_history.node, node)

    def find_last_invoke(self, state):
        history = state.history.parent
        while history:
            # if history.invoke_addr:
                # return history
            if history in self.hs:
                return self.hs[history]
            history = history.parent

    def repr_constraints(self, state):
        cs = []
        if state.solver.constraints:
            for c in state.solver.constraints:
                cs.append(str(c).replace('<', '').replace('>', ''))
        return cs
        # return copy.deepcopy(state.solver.constraints)

    def find_constraint_addtion(self, state, src, des):
        cs = []
        for c in des.constraints:
            if c not in src.constraints:
                cs.append(str(c).replace('<', '').replace('>', ''))
        return cs

    def view(self):
        fp = '../results/ToGoProject/{}.dot'.format(self.start)
        nx.drawing.nx_agraph.write_dot(self.g, fp)

    def add_simple_node(self, ea, description, state):
        context = MachO.resolve_context(ea)
        context_name = Function.meth_data[context]['name']
        node = INVOKEFS.format(hex(context), context_name, state.history.depth, hex(ea), description, '')
        if node not in self.g.nodes:
            self.g.add_node(node, des=description, context=context, context_name=context_name)
            self.hs[state.history] = hs(ea, self.repr_constraints(state), node)
        return node

    def add_start_node(self, ea, description, state, edge=None):
        node = self.add_simple_node(ea, description, state)
        self.g.nodes[node]['color'] = 'blue'

        # if edge:
        #     last_invoke_history = self.find_last_invoke(state)
        #     self.g.add_edge(last_invoke_history.node, node)

        if not self.start:
            self.start = "{}{}".format(hex(self.g.nodes[node]['context']), self.g.nodes[node]['context_name'])


    def expr_args(self, args):
        expr = ''
        if args:
            for i in range(0, len(args)):
                reg_name = 'x' + str(i)
                reg_value = args[i]
                expr += '{}: {}\n'.format(reg_name, reg_value)
        return expr


class hs:
    def __init__(self, ea, cs, node):
        self.node = node
        self.invoke_addr = ea
        self.constraints = cs


