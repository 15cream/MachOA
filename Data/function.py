__author__ = 'gjy'

from Data.invokenode import InvokeNode
import re
from class_o import class_o


class Function:

    meth_list = []
    meth_data = dict()

    def __init__(self, addr, state):
        self.name = None
        self.start = addr
        self.end = None
        self.invokes = dict() # state_addr, invoke_node
        self.state = state
        self.start_node = None
        self.build_start_node()
        self.retVal = None

    @staticmethod
    def build_meth_list():
        Function.meth_list = sorted(class_o.classes_indexed_by_meth.keys())
        for meth_imp in Function.meth_list:
            if meth_imp not in Function.meth_data:
                Function.meth_data[meth_imp] = {'name':class_o.classes_indexed_by_meth[meth_imp][0],
                                                'class':class_o.classes_indexed_by_meth[meth_imp][1]}

    def init_state(self):
        if self.start in Function.meth_list:
            meth_data = Function.meth_data[self.start]
            print " * * * * * * * * * * * Analyze method {} at {}  * * * * * * * * * * * ".format(meth_data['name'], hex(self.start))
            class_data = meth_data['class']
            if self.start in class_data.instance_meths:
                classname = meth_data['class'].name
                self.state.regs.x0 = self.state.solver.BVS(classname + "_instance", 64)
            else:
                classref = meth_data['class'].classref_addr
                self.state.regs.x0 = self.state.solver.BVV(classref, 64)

    def build_start_node(self):
        start_node = InvokeNode(self.start)
        start_node.set_description("Start")
        self.start_node = start_node
        self.invokes[self.state.history] = start_node

    def resolve_dependency(self, receiver):
        match = re.search('ret_from_(?P<addr>\w+?)L_.*', receiver)
        if match:
            d_addr = int(match.group('addr'), 16)
            for node in self.invokes.values():
                if d_addr == node.addr:
                    return node
        else:
            return None

    def insert_invoke(self, state, ins_addr, selector, receiver):
        node = InvokeNode(ins_addr)
        node.set_deps('receiver', self.resolve_dependency(receiver))
        node.set_description('[' + receiver + ' ' + selector + ']')
        history = state.history
        if history not in self.invokes:
            self.invokes[history] = node
        while True:
            history = history.parent
            if history in self.invokes:
                self.invokes[history].add_child(node)
                break

    def godown(self, node, callstring):
        callstring.append(node)
        if node.next:
            for child in node.next:
                self.godown(child, callstring)
        else:
            for c in callstring:
                print str(hex(c.addr)), c.description,  '->',
            print 'End'
        callstring.pop()

    def print_call_string(self):
        callstring = []
        node = self.start_node
        self.godown(node, callstring)

    def setRetVal(self, val):
        self.retVal = val