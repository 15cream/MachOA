import xml.etree.ElementTree as ET
from graph_tool.all import *


class CallGraph:

    def __init__(self, file=None):
        self.tree = ET.parse(file)
        self.root = self.tree.getroot()
        self.g = Graph()
        self.node_vertex = dict() # key:node_addr, value: vertex

    def build(self):
        vp = self.g.new_vertex_property("object")
        self.link(self.find_start_node(vp), vp)
        self.g.vertex_properties['info'] = vp

    def find_start_node(self, vp):
        for node in self.root.iter('NODE'):
            if node.text == 'Start':
                return node
        return None

    def link(self, node, vp):
        source = self.build_vertex(node, vp)
        for next in node.findall('NEXT'):
            next_node = self.root.findall("./NODE[@addr='{}']".format(next.get('addr'))).pop()
            self.g.add_edge(source, self.build_vertex(next_node, vp))
            self.link(next_node, vp)

    def build_vertex(self, node, vp):
        if node.get('addr') not in self.node_vertex:
            n = self.g.add_vertex()
            self.node_vertex[node.get('addr')] = n
            vp[n] = {'addr': node.get('addr'), 'description': node.text}
            return n
        else:
            return self.node_vertex[node.get('addr')]

    def output(self):
        graph_draw(self.g, vertex_text=self.g.vertex_index, vertex_size=7, vertex_font_size=10,
                   output_size=(1280, 1280), output="two-nodes.png")

from graphviz import Digraph

dot = Digraph(comment='The Test Table')

# 添加圆点A,A的标签是Dot A
dot.node('A', 'Dot A')

# 添加圆点 B, B的标签是Dot B
dot.node('B', 'Dot B')
# dot.view()

# 添加圆点 C, C的标签是Dot C
dot.node('C', 'Dot C')
# dot.view()

# 创建一堆边，即连接AB的两条边，连接AC的一条边。
dot.edges(['AB', 'AC', 'AB'])
# dot.view()

# 在创建两圆点之间创建一条边
dot.edge('B', 'C', 'test')
# dot.view()


# 获取DOT source源码的字符串形式
print(dot.source)
# // The Test Table
# digraph {
#   A [label="Dot A"]
#   B [label="Dot B"]
#   C [label="Dot C"]
#   A -> B
#   A -> C
#   A -> B
#   B -> C [label=test]
# }


# 保存source到文件，并提供Graphviz引擎
dot.render('test-output/test-table.gv', view=True)