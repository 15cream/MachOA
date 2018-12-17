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
            # if 'e0c' not in f:
            #     continue
            try:
                g = nx.drawing.nx_agraph.read_dot(p + f)
                print f
                for node in g.nodes:
                    print '-' * 80
                    ea = g.nodes[node]['addr']
                    des = g.nodes[node]['des']
                    rec = g.nodes[node]['rec']
                    args = g.nodes[node]['args'] if 'args' in g.nodes[node] else None

                    print hex(int(ea, 10)), des
                    print 'Receiver: {} \nArguments:'.format(rec)
                    if args:
                        print args
            except Exception as e:
                pass


cs = CallString()
cs.recover_from_path('../results/AppJobber_arm64/')
# cs.recover_from_path('../results/DoubanRadio_arm64/')

