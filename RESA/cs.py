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
                            'eTree': 'this could be none because of too mush mem needed.',
                            'invoke': ''
                        }
                }
        }

    def recover_from_path(self, p):
        for f in os.listdir(p):
            # if '0x1002f33f0' not in f:
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
cs.recover_from_path('../results/CsdnPlus_arm64/')
# cs.recover_from_path('../results/DoubanRadio_arm64/')

# for node in g.nodes:
#     # if g.nodes[node]['sel'] == 'identifierForVendor':
#     if '0x100326d88' in g.nodes[node]['rec'] or 'args' in g.nodes[node] and '0x100326d88' in g.nodes[node]['args']:
#         ea = g.nodes[node]['addr']
#         des = g.nodes[node]['des']
#         rec = g.nodes[node]['rec']
#         args = g.nodes[node]['args'] if 'args' in g.nodes[node] else None
#
#         print hex(int(ea, 10)), des
#         print 'Receiver: {} \nArguments:'.format(rec)
#         if args:
#             print args

