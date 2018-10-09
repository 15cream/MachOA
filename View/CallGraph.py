import xml.etree.ElementTree as ET
from graphviz import Digraph
import os
import sys


class CallGraph:

    def __init__(self, file=None):
        self.tree = ET.parse(file)
        self.root = self.tree.getroot()
        self.g = Digraph(comment=self.root.get('name'))
        self.vertexs = []

    def build(self):
        self.build_vertexs()
        self.build_edges()

    def build_vertexs(self):
        for node in self.root.iter('NODE'):
            addr = node.get('addr')
            self.g.node(addr, label=addr + " " + node.text)

    def build_vertexs_2(self):
        for node in self.root.iter('NODE'):
            addr = node.get('addr')
            self.g.node(addr, label=addr + " " + node.text)

    def build_edges(self):
        edges = []
        for node in self.root.iter('NODE'):
            src = node.get('addr')
            for next in node.findall('NEXT'):
                des = next.get('addr')
                edge = [src, des]
                if edge in edges:
                    continue
                else:
                    edges.append(edge)
                    self.g.edge(src, des)

    def output(self, file):
        self.g.render(file, view=True)



# cg = CallGraph('/home/gjy/Desktop/MachOA/xmls/+[TGHttpManager TGEncryptPOSTWithURLString:parameters:name:type:showLoading:showError:loginInvalid:success:failure:].xml')
# cg.build()
# cg.output('/home/gjy/Desktop/MachOA/visualize/cgs/+[TGHttpManager TGEncryptPOSTWithURLString:parameters:name:type:showLoading:showError:loginInvalid:success:failure:].pdf')




