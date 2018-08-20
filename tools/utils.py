import os
from graphviz import Digraph
import re

def check_files_in_dir(dirpath):
    class_checked = []
    if os.path.isdir(dirpath):
        for f in os.listdir(dirpath):
            classname = f.split('.')[0]
            class_checked.append(classname)
    return class_checked


def find_refs(refed=None):
    dirpath = '../dds/ToGoProject/'
    related = []
    if os.path.isdir(dirpath):
        for f in os.listdir(dirpath):
            classname = f.split('.')[0]
            fp = open(dirpath + f)
            content = fp.read()
            if refed in content:
                related.append(classname)
                # find_invoke(refed, dirpath + f)
            fp.close()
    return related


def find_invokes(refed=None):
    dirpath = '../dds/ToGoProject/'
    related = []
    if os.path.isdir(dirpath):
        for f in os.listdir(dirpath):
            classname = f.split('.')[0]
            fp = open(dirpath + f)
            content = fp.read()
            if refed in content:
                invokes = find_invoke(refed, dirpath + f)
                for func, invoke in invokes.items():
                    for i in invoke:
                        # i = re.sub('^[x0-9A-Fa-fL]+', '', i)
                        related.append("{} -> \n    {}  ".format(func, i).strip())
            fp.close()
    return related

def find_invoke(referred, fp):
    invokes = dict()
    if os.path.isfile(fp):
        func = None
        f = open(fp)
        for line in f.readlines():
            m = re.search('-+(?P<func>[-+]\[.*\])-+', line)
            if m:
                func = m.group('func')
                continue
            if referred in line:
                if func in invokes:
                    invokes[func].append(line)
                else:
                    invokes[func] = [line, ]
        f.close()
    print 'FIND REF TO {}:'.format(referred)
    print invokes
    return invokes


def build_web(from_class=None):
    center = Node().set_name(from_class)
    trace(center)
    Node.visualize()
    pass


def trace(node):
    backwards = find_refs(node.name)
    if backwards:
        node.set_parent(backwards)
        for p in node.parent:
            if p.isNotHistory():
                trace(p)
    else:
        return



class Node:

    nodes = dict()

    @staticmethod
    def get_node(name):
        if name in Node.nodes:
            return Node.nodes[name]
        else:
            node = Node().set_name(name)
            Node.nodes[name] = node
            return node

    def __init__(self):
        self.parent = []
        self.node = self
        self.name = None
        self.next = []
        self.history = [self,]

    # input is a list of classnames
    def set_parent(self, list):
        for p in list:
            pnode = Node.get_node(p)
            pnode.set_next(self)
            self.parent.append(pnode)

    def set_name(self, name):
        self.name = name
        return self

    def set_next(self, next):
        nnode = Node.get_node(next.name)
        if nnode not in self.next:
            self.next.append(nnode)
            self.history.extend(nnode.history)

    def isNotHistory(self):
        if self in self.history[1:]:
            return False
        else:
            return True

    @staticmethod
    def visualize():
        g = Digraph()
        for classname, classnode in Node.nodes.items():
            g.node(str(classname))
            for n in classnode.next:
                g.edge(str(n.name), str(classname))
        g.render(view=True)




# print "\n".join(find_refs(refed='TGHttpManager'))
# build_web(from_class='[TGHttpManager TGEncryptPOSTWithURLString:parameters:name:type:showLoading:showError:loginInvalid:success:failure:]')

