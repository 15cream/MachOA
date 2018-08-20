__author__ = 'gjy'

import xml.etree.ElementTree as ET

class InvokeNode:

    def __init__(self, addr):
        self.addr = addr
        self.description = ''
        self.next = []
        self.parents = []
        self.dependencies = dict()
        self.receiver = None
        self.selector = None
        self.args = []
        self.expr = None  # used for dependency

    def add_child(self, invoke):
        self.next.append(invoke)

    def add_parent(self, invoke):
        self.parents.append(invoke)

    def set_description(self, description):
        self.description = description

    def set_receiver(self, r):
        self.receiver = r

    def set_selector(self, s):
        self.selector = s

    def set_args(self, args):
        self.args = args

    def set_deps(self, key, node):
        if key not in self.dependencies:
            self.dependencies[key] = node

    def get_expr(self):
        if not self.expr:
            if self.dependencies and self.dependencies['receiver']:
                self.expr = "[{} {}]".format(self.dependencies['receiver'].get_expr(), self.selector)
            else:
                self.expr = self.description
        return self.expr


    def xmlNode(self):
        node = ET.Element('NODE')
        node.set('addr', hex(self.addr))
        for next in self.next:
            nn = ET.Element('NEXT')
            nn.set('addr', hex(next.addr))
            node.append(nn)
        node.text = self.description
        return node
