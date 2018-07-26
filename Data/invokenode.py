__author__ = 'gjy'


class InvokeNode:

    def __init__(self, addr):
        self.addr = addr
        self.description = ''
        self.next = []
        self.parents = []
        self.dependencies = dict()

    def add_child(self, invoke):
        self.next.append(invoke)

    def add_parent(self, invoke):
        self.parents.append(invoke)

    def set_description(self, description):
        self.description = description

    def set_deps(self, key, node):
        if key not in self.dependencies:
            self.dependencies[key] = node
