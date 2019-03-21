# coding=utf-8
import networkx as nx
import random
from Data.CONSTANTS import *
from Data.data import *
from BinaryPatch.Utils import *
from RuntimePatch.Utils import *
from RuntimePatch.ConstraintHelper import *
from RuntimePatch.DependencyResolve import DPResolver

class GraphView:

    def __init__(self):
        """
        * Graph attributes *
        node['des']: description, -[rec sel] or sub_X.
        node['rec']: receiver
        node['sel']: selector
        node['context']: the context ea.
        node['addr']: where the invoke happens.
        node['args']: the arguments for this invoke.
        node['dp']: the database dependency. (None default)
        node['pnode']: the predecessor node. (None if the start node.)
        node['snode']: the successor node.
        edge['color']: green if intra-procedural, red if inter-procedural.
        edge['label']: constraints.

        * history_records *
        Use the SimState.history as key, HS instance as value.

        :return:
        """
        self.g = nx.DiGraph()
        self.history_records = dict()
        self.start = None
        self.dpr = DPResolver(self.g, self)

        self.g.graph['start'] = None
        self.g.graph['ret'] = set()
        self.g.graph['data_usage'] = {}

    def insert_invoke(self, ea, description, state, args=None, receiver=None, selector=None):
        """
        Insert invoke node in the eTree.
        :param ea: the address where message send
        :param description: the string used to describe invoked method
        :param state:
        :param args:
        :param receiver:
        :param selector:
        :return:
        """
        context = resolve_context(ea)
        if context in OCFunction.oc_function_set:
            context_name = OCFunction.oc_function_set[context].expr
        else:
            context_name = OCFunction.meth_data[context]['name']

        # Add node.
        node = INVOKEFS.format(hex(context), context_name, state.history.depth, hex(ea), description, expr_args(args))
        if node not in self.g.nodes:
            self.g.add_node(node, des=description, context=context, context_name=context_name, addr=ea, args=expr_args(args), dp=None,
                            rec=receiver, sel=selector)
        else:
            pass  # Invoke again. (Impossible ?)
            # print "Invoke has been recorded: {}".format(node)

        # Record this invoke.
        self.history_records[state.history] = HS(ea, repr_constraints(state), node)

        # Add the edge. Because path sensitive, one predecessor only.
        last_invoke_history = self.find_last_invoke(state)
        if last_invoke_history:
            self.g.nodes[node]['pnode'] = last_invoke_history.node
            color = 'red' if self.g.nodes[last_invoke_history.node]['context'] != self.g.nodes[node]['context'] \
                else 'green'
            lable = '\n'.join(find_constraint_addtion(self.history_records[state.history], last_invoke_history))
            self.g.add_edge(last_invoke_history.node, node, lable='', color=color)
        else:
            self.g.nodes[node]['pnode'] = None

        # self.dpr.resolve_dp(node)
        # print self.g.nodes[node]['dp']
        return node

    def add_simple_node(self, ea, description, state, args=None, type=None):
        context = resolve_context(ea)
        if context in OCFunction.oc_function_set:
            context_name = OCFunction.oc_function_set[context].expr
        else:
            context_name = OCFunction.meth_data[context]['name']

        if type == 'RET':
            node = RETFS.format(description, hex(ea), random.uniform(0, 10))
        else:
            node = INVOKEFS.format(hex(context), context_name, state.history.depth, hex(ea), description, expr_args(args))
        if node not in self.g.nodes:
            self.g.add_node(node, des=description, context=context, context_name=context_name, addr=ea,
                            args=expr_args(args), dp=None, pnode=None, rec=None, sel=None)
            self.history_records[state.history] = HS(ea, repr_constraints(state), node)
        return node

    def add_start_node(self, ea, description, state, edge=None, args=None):
        node = self.add_simple_node(ea, description, state, args=args)
        self.g.nodes[node]['color'] = 'blue'
        if not self.start:
            self.start = "{}{}".format(hex(self.g.nodes[node]['context']), self.g.nodes[node]['context_name'])
            self.g.graph['start'] = node
        if edge:
            last_invoke_history = self.find_last_invoke(state)
            self.g.add_edge(last_invoke_history.node, node)

    def add_ret_node(self, ea, state, ret_value):
        # 返回值有时是一致的，区分在于其前向节点是什么。
        node = self.add_simple_node(ea, ret_value, state, type='RET')
        self.g.nodes[node]['color'] = 'green'
        self.g.nodes[node]['ret'] = ret_value
        if 'ret' not in self.g.graph:
            self.g.graph['ret'] = set(node)
        else:
            self.g.graph['ret'].add(node)
        last_invoke_history = self.find_last_invoke(state)
        self.g.add_edge(last_invoke_history.node, node)

    def find_last_invoke(self, state):
        history = state.history.parent
        while history:
            if history in self.history_records:
                return self.history_records[history]
            history = history.parent

    def find_pnode(self, node, p_addr):
        p_node = node
        while p_node:
            p_node = self.g.nodes[p_node]['pnode']
            if p_node and hex(self.g.nodes[p_node]['addr']) == p_addr:
                return p_node
        return None

    def view(self):
        fp = '{}{}/{}.dot'.format(MachO.pd.task.configs.get('PATH', 'results'), MachO.pd.macho.provides, self.start)
        try:
            nx.drawing.nx_agraph.write_dot(self.g, fp)
            return fp
        except Exception as e:
            print 'Failed to generate {}, {} '.format(fp, e)
            return None


class HS:
    def __init__(self, ea, cs, node):
        self.node = node
        self.invoke_addr = ea
        self.constraints = cs
