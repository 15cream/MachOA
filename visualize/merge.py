import networkx as nx


class CfgMerge:

    def __init__(self, filepath):
        self.g = nx.drawing.nx_agraph.read_dot(filepath)
        self.start_addr = hex(int(filepath.split('/')[-1].split('_')[0]))
        self.checked = []

    def build(self):
        self.wipe_extras()
        self.traverse(self.start_addr)

    def wipe_extras(self):
        node_list = self.g.node.keys()
        for n in node_list:
            if self.g.in_degree(n) == 0 and n != self.start_addr:
                self.g.remove_node(n)

    def traverse(self, node):
        self.checked.append(node)
        successors = list(self.g.neighbors(node))
        if len(successors) == 1:
            s = successors[0]
            if self.g.in_degree[s] == 1:
                self.merge(node, s)
                self.traverse(node)
            else:
                self.traverse(s) if not self.loop(s) else None
        elif not successors:
            return
        else:
            for s in successors:
                self.traverse(s) if not self.loop(s) else None

    def merge(self, retain, to_be_merged):
        for successor in self.g.neighbors(to_be_merged):
            self.g.add_edge(retain, successor)
        self.g.remove_node(to_be_merged)

    def loop(self, node):
        if node in self.checked:
            return True
        else:
            return False

    def output(self, output):
        nx.drawing.nx_agraph.write_dot(self.g, output)



cm = CfgMerge("/home/gjy/Desktop/AL/files/cff-act-3_bak/reverse/1528_recovered.dot")
cm.build()
nx.drawing.nx_agraph.view_pygraphviz(cm.g)
nx.drawing.nx_agraph.write_dot(cm.g,'file.dot')

