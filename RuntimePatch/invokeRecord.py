import networkx as nx
from Data.binary import MachO
from Data.function import Function
from Data.CONSTANTS import *
import copy
import claripy

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

        self.hs[state.history] = hs(ea, self.repr_constraints(state), node)

        last_invoke_history = self.find_last_invoke(state)
        if last_invoke_history:
            color = 'red' if self.g.nodes[last_invoke_history.node]['context'] != self.g.nodes[node]['context'] else 'green'
            self.g.add_edge(last_invoke_history.node, node,
                            # label='\n'.join(self.find_constraint_addtion(state, last_invoke_history, self.hs[state.history])),
                            color=color)
            self.g.nodes[node]['pnode'] = last_invoke_history.node
        else:
            self.g.nodes[node]['pnode'] = None
            # print "from {} to {}".format(last_invoke_history.node, node)

        self.secheck(state, node)
        return node


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
        fp = '../results/{}/{}.dot'.format(MachO.pd.macho.provides, self.start)
        nx.drawing.nx_agraph.write_dot(self.g, fp)

    def add_simple_node(self, ea, description, state):
        context = MachO.resolve_context(ea)
        context_name = Function.meth_data[context]['name']
        node = INVOKEFS.format(hex(context), context_name, state.history.depth, hex(ea), description, '')
        if node not in self.g.nodes:
            self.g.add_node(node, des=description, context=context, context_name=context_name, addr=ea, args=None, dp=None, pnode=None)
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

    def secheck(self, state, node):
        receiver = self.g.nodes[node]['args'][0]
        selector = self.g.nodes[node]['args'][1]

        if receiver in RECEIVERS or selector in SELECTORS or self.has_tainted_vals(state, node):
            self.resolve_dp(node)
            self.taint(state, node)
            print 'SINK: ', self.g.nodes[node]['dp']

    def taint(self, state, node):
        count = len(self.g.nodes[node]['args'])
        for i in range(0, count):
            state.regs.get("x{}".format(i)).ast.__setattr__('tainted', True)
        self.g.nodes[node]['tainted'] = True

    def has_tainted_vals(self, state, node):
        count = len(self.g.nodes[node]['args'])
        for i in range(0, count):
            if 'tainted' in state.regs.get("x{}".format(i)).ast.__dict__:
                if state.regs.get("x{}".format(i)).ast.tainted:
                    return True
        return False

    def resolve_receiver(self, state, node):
        receiver = self.g.nodes[node]['args'][0]
        if 'RetFrom' in receiver:
            src_node = self.find_pnode(node, receiver.split('_')[-1])
            if src_node:
                if not self.g.nodes[src_node]['dp']:
                    self.resolve_dp(src_node)
                receiver = self.g.nodes[src_node]['dp'].split(' ')[0].strip('[')
        return receiver

    def resolve_dp(self, node):
        dps = []
        try:
            for d in self.g.nodes[node]['args']:
                if 'RetFrom' in d:
                    src_node = self.find_pnode(node, d.split('_')[-1])
                    if src_node and 'Symbol' not in str(self.g.nodes[src_node]['des']):
                        if not self.g.nodes[src_node]['dp']:
                            self.resolve_dp(src_node)
                        dps.append(self.g.nodes[src_node]['dp'])
                    else:
                        dps.append(d)
                else:
                    dps.append(d)
        except TypeError as e:
            print e
        receiver = dps[0]
        selector = dps[1]
        s = ''
        i = 2
        try:
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
        except IndexError as e:
            print e
        expr = '[{} {}]'.format(receiver, s)
        self.g.nodes[node]['dp'] = expr
        return expr

    def find_pnode(self, node, p_addr):
        p_node = node
        while p_node:
            p_node = self.g.nodes[p_node]['pnode']
            if p_node and hex(self.g.nodes[p_node]['addr']) == p_addr:
                return p_node
        return None

class hs:
    def __init__(self, ea, cs, node):
        self.node = node
        self.invoke_addr = ea
        self.constraints = cs



