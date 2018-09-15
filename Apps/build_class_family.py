import pickle
import networkx as nx

class OCClass:

    class_dict = dict()  # key: class_name; value: OCClass object ; classes in __objc_classrefs
    imports = [] # class_name string
    classlist = []  # class_name string, implemented in binary

    def __init__(self, name):
        self.name = name
        self._in = []
        self._out = []

    def insert_callee(self, c):
        if c not in self._out:
            self._out.append(c)

    def insert_caller(self, c):
        if c not in self._in:
            self._in.append(c)

    def find_convergence(self):
        root = self
        class_set = []
        root.find_children(class_set)
        return class_set

    def find_children(self, class_set):
        for c in self._out:
            if c not in class_set:
                class_set.append(c)
                c.find_children(class_set)

    @staticmethod
    def buildRefs(db):
        input = open(db, 'rb')
        [classes, OCClass.imports, OCClass.classlist] = pickle.load(input)
        input.close()
        for c in classes:
            if c not in OCClass.class_dict:
                cc = OCClass(c)
                OCClass.class_dict[c] = cc
                for xref in classes[c]:
                    if xref in OCClass.class_dict:
                        xrefc = OCClass.class_dict[xref]
                    else:
                        xrefc = OCClass(xref)
                        OCClass.class_dict[xref] = xrefc
                    xrefc.insert_callee(cc)
                    cc.insert_caller(xrefc)

    @staticmethod
    def visualize():
        G = nx.DiGraph()
        for c, cc in OCClass.class_dict.items():
            if c in OCClass.classlist:
                for cl in cc.find_convergence():
                    if cl.name in OCClass.classlist:
                        G.add_edge(c, cl.name)
        nx.drawing.nx_agraph.view_pygraphviz(G)
        nx.drawing.nx_agraph.write_dot(G, 'refs.dot')


OCClass.buildRefs('/home/gjy/Desktop/idapython/crefs.pkl')
OCClass.visualize()


