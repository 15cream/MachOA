# _*_coding:utf-8_*_
import networkx as nx
from Data.CONSTANTS import *

from BinaryPatch.Utils import *
from RuntimePatch.ConstraintHelper import *
from RuntimePatch.Utils import *
from RuntimePatch.DependencyResolve import DPResolver


class GraphView:

    def __init__(self):
        self.g = nx.DiGraph()
        self.hs = dict()
        self.start = None
        self.dpr = DPResolver(self.g, self)

    def insert_invoke(self, ea, description, state, args=None, receiver=None, selector=None):
        # ea : where the invoke happens
        # description could be function name or symbol name
        context = resolve_context(ea)
        context_name = OCFunction.meth_data[context]['name']
        node = INVOKEFS.format(hex(context), context_name, state.history.depth, hex(ea), description, expr_args(args))
        if node not in self.g.nodes:
            self.g.add_node(node, des=description, context=context, addr=ea, args=args, dp=None)
        else:
            # print 'COME TO THIS INVOKE AGAIN. -> {}'.format(hex(ea))
            pass

        self.hs[state.history] = hs(ea, repr_constraints(state), node)

        last_invoke_history = self.find_last_invoke(state)
        if last_invoke_history:
            color = 'red' if self.g.nodes[last_invoke_history.node]['context'] != self.g.nodes[node]['context'] else 'green'
            self.g.add_edge(last_invoke_history.node, node,
                            # label='\n'.join(self.find_constraint_addtion(state, last_invoke_history, self.hs[state.history])),
                            color=color)
            self.g.nodes[node]['pnode'] = last_invoke_history.node
        else:
            self.g.nodes[node]['pnode'] = None
        self.dpr.resolve_dp(node)
        # print self.g.nodes[node]['dp']
        return node

    def add_simple_node(self, ea, description, state):
        context = resolve_context(ea)
        context_name = OCFunction.meth_data[context]['name']
        node = INVOKEFS.format(hex(context), context_name, state.history.depth, hex(ea), description, '')
        if node not in self.g.nodes:
            self.g.add_node(node, des=description, context=context, context_name=context_name, addr=ea, args=None, dp=None, pnode=None)
            self.hs[state.history] = hs(ea, repr_constraints(state), node)
        return node

    def add_start_node(self, ea, description, state, edge=None):
        node = self.add_simple_node(ea, description, state)
        self.g.nodes[node]['color'] = 'blue'
        if not self.start:
            self.start = "{}{}".format(hex(self.g.nodes[node]['context']), self.g.nodes[node]['context_name'])
            # if edge:
            #     last_invoke_history = self.find_last_invoke(state)
            #     self.g.add_edge(last_invoke_history.node, node)

    def find_last_invoke(self, state):
        history = state.history.parent
        while history:
            if history in self.hs:
                return self.hs[history]
            history = history.parent

    def find_pnode(self, node, p_addr):
        p_node = node
        while p_node:
            p_node = self.g.nodes[p_node]['pnode']
            if p_node and hex(self.g.nodes[p_node]['addr']) == p_addr:
                return p_node
        return None

    def view(self):
        fp = '../results/{}/{}.dot'.format(MachO.pd.macho.provides, self.start)
        try:
            nx.drawing.nx_agraph.write_dot(self.g, fp)
        except Exception as e:
            print 'Failed to generate {}, {} '.format(fp, e)


class hs:
    def __init__(self, ea, cs, node):
        self.node = node
        self.invoke_addr = ea
        self.constraints = cs



