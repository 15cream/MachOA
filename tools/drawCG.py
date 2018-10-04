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

    def insert_invoke(self, ea, description, state, args=None, receiver=None, selector=None):
        # ea : where the invoke happens
        # description could be function name or symbol name
        context = MachO.resolve_context(ea)
        context_name = Function.meth_data[context]['name']
        node = INVOKEFS.format(hex(context), context_name, state.history.depth, hex(ea), description, self.expr_args(args))
        if node not in self.g.nodes:
            self.g.add_node(node, des=description, context=context, addr=ea, args=args, dp=None)
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
        self.g.nodes[node]['pnode'] = last_invoke_history.node
        # print "from {} to {}".format(last_invoke_history.node, node)

        self.secheck(node)


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

    def secheck(self, node):
        receiver = self.g.nodes[node]['args'][0]
        selector = self.g.nodes[node]['args'][1]
        if receiver == 'NSURLConnection' or selector == 'initWithRequest:delegate:startImmediately:':
        # if True:
            self.resolve_dp(node)
            print 'SINK: ', self.g.nodes[node]['dp']

    def resolve_dp(self, node):
        dps = []
        for d in self.g.nodes[node]['args']:
            if 'RetFrom' in d:
                src_node = self.find_pnode(node, d.split('_')[-1])
                if not self.g.nodes[src_node]['dp']:
                    self.resolve_dp(src_node)
                dps.append(self.g.nodes[src_node]['dp'])
            else:
                dps.append(d)
        receiver = dps[0]
        selector = dps[1]
        s = ''
        i = 2
        if ':' in selector:
            for c in selector.split(':'):
                if c:
                    s += "{}:{} ".format(c, dps[i])
                    i += 1
            if selector == 'stringWithFormat:':
                fsa = ",".join(dps[3:-1])
                s = "{}({})".format(s, fsa)
        else:
            s = selector
        expr = '[{} {}]'.format(receiver, s)
        self.g.nodes[node]['dp'] = expr
        return expr

    def find_pnode(self, node, p_addr):
        p_node = node
        while True:
            p_node = self.g.nodes[p_node]['pnode']
            if hex(self.g.nodes[p_node]['addr']) == p_addr:
                return p_node

class hs:
    def __init__(self, ea, cs, node):
        self.node = node
        self.invoke_addr = ea
        self.constraints = cs


