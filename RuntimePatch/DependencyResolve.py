
class DPResolver():
    def __init__(self, g, view):
        self.g = g
        self.view = view

    def resolve_dp(self, node):
        if self.g.nodes[node]['dp']:
            return self.g.nodes[node]['dp']
        dps = []
        try:
            for d in self.g.nodes[node]['args']:
                if 'RetFrom' in d:
                    src_node = self.view.find_pnode(node, d.split('_')[-1])
                    if src_node and 'Symbol' not in str(self.g.nodes[src_node]['des']):
                        if not self.g.nodes[src_node]['dp']:
                            self.resolve_dp(src_node)
                        dps.append(self.g.nodes[src_node]['dp'])
                    else:
                        dps.append(d)
                else:
                    dps.append(d)
        except TypeError as e:
            print e
        receiver = dps[0]
        selector = dps[1]
        s = ''
        i = 2
        try:
            if ':' in selector:
                for c in selector.split(':'):
                    if c:
                        s += "{}:{} ".format(c, dps[i])
                        i += 1
                if selector == 'stringWithFormat:':
                    fsa = ",".join(dps[3:-1])
                    s = "{}({})".format(s, fsa)
            else:
                s = selector
        except IndexError as e:
            print e
        expr = '[{} {}]'.format(receiver, s)
        self.g.nodes[node]['dp'] = expr
        return expr