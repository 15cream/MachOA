import os
import networkx as nx


class CallString:

    def __init__(self):
        self.cs = {
            'sampleClass':
                {
                    'sampleMethod':
                        {
                            'dot': 'dot_file_path',
                            'graph': 'this could be none because of too mush mem needed.',
                            'invoke': ''
                        }
                }
        }

    def recover_from_path(self, p):
        for f in os.listdir(p):
            if '0x100007ec8' not in f:
                continue
            g = nx.drawing.nx_agraph.read_dot(p+f)
            print f
            for node in g.nodes:
                print hex(int(g.nodes[node]['addr'], 10)), g.nodes[node]['dp']

cs = CallString()
cs.recover_from_path('../results/AppJobber_arm64/')

