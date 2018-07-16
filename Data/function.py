__author__ = 'gjy'

from Data.invokenode import InvokeNode


class Function:
    def __init__(self, addr, state):
        self.name = None
        self.start = addr
        self.end = None
        self.invokes = dict() # state_addr, invoke_node
        self.state = state
        self.start_node = None
        self.build_start_node()

    def build_start_node(self):
        start_node = InvokeNode(self.start)
        start_node.set_description("Start")
        self.start_node = start_node
        self.invokes[self.state.history] = start_node

    def insert_invoke(self, state, ins_addr, description):
        node = InvokeNode(ins_addr)
        node.set_description(description)
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
                print str(hex(c.addr)), c.description + '->',
            print 'End'
        callstring.pop()

    def print_call_string(self):
        callstring = []
        node = self.start_node
        self.godown(node, callstring)