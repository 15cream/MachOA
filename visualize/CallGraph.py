import xml.etree.ElementTree as ET
from graphviz import Digraph


class CallGraph:

    def __init__(self, file=None):
        self.tree = ET.parse(file)
        self.root = self.tree.getroot()
        self.g = Digraph(comment=self.root.get('name'))
        self.vertexs = []

    def build(self):
        self.link(self.find_start_node())

    def find_start_node(self):
        for node in self.root.iter('NODE'):
            if node.text == 'Start':
                return node
        return None

    def link(self, node):
        source = self.build_vertex(node)
        for next in node.findall('NEXT'):
            next_node = self.root.findall("./NODE[@addr='{}']".format(next.get('addr'))).pop()
            self.g.edge(source, self.build_vertex(next_node))
            self.link(next_node)

    def build_vertex(self, node):
        addr = node.get('addr')
        if addr not in self.vertexs:
            n = self.g.node(addr, label=addr + " " + node.text)
            self.vertexs.append(addr)
            return addr
        else:
            return addr

    def output(self):
        self.g.render('test.gv', view=True)


cg = CallGraph('test.xml')
cg.build()
cg.output()




