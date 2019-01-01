import os
import re
import networkx as nx


class ScenarioExtractor:
    def __init__(self, seeds=None, dir=None):
        self.seeds = seeds
        self.dir = dir
        self.graph = None
        self.graph_indexed_by_invoke_ea = dict()
        self.graph_indexed_by_invoke_dp = dict()
        self.node_and_dps = dict()
        self.scenario_set = []

    def parse_all_traces(self):
        for f in os.listdir(self.dir):
            cfg_file = os.path.join(self.dir, f)
            print cfg_file
            try:
                self.parse_cfg(cfg_file)
            except Exception as e:
                print e

    def parse_cfg(self, cfg_file):
        """
        Give a call-graph file (inter-procedural or intra-procedural), parse this cfg and extract scenarios.
        :param cfg_file:
        :return:
        """
        # Actually, because of the path sensitivity, one cfg covers several traces.
        self.scenario_set = []
        self.graph = nx.drawing.nx_agraph.read_dot(cfg_file)
        for node, node_data in self.graph.nodes.items():
            self.node_and_dps[node] = set()
            ea = int(node_data['addr'])
            if ea in self.graph_indexed_by_invoke_ea:
                self.graph_indexed_by_invoke_ea[ea].append(node)
            else:
                self.graph_indexed_by_invoke_ea[ea] = [node, ]

            if 'rec' in node_data:
                m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', node_data['rec'])
                if m:
                    ptr = int(m.group('ptr').encode('UTF-8').strip('L'), 16)
                    if ptr in self.graph_indexed_by_invoke_dp:
                        self.graph_indexed_by_invoke_dp[ptr].append((node, 'rec'))
                    else:
                        self.graph_indexed_by_invoke_dp[ptr] = [(node, 'rec'), ]
                    self.node_and_dps[node].add(ptr)

            if 'args' in node_data:
                args = node_data['args'].split('\n')[0:-1]
                for arg in args:
                    m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', arg)
                    if m:
                        ptr = int(m.group('ptr').encode('UTF-8').strip('L'), 16)
                        if ptr in self.graph_indexed_by_invoke_dp:
                            self.graph_indexed_by_invoke_dp[ptr].append((node, 'arg'))
                        else:
                            self.graph_indexed_by_invoke_dp[ptr] = [(node, 'arg'), ]
                        self.node_and_dps[node].add(ptr)

        # initial scenarios for each node matched seed.
        for node in self.match_seed():
            self.scenario_set.append(Scenario(node))

        for scenario in self.scenario_set:
            self.construct(scenario)

    def match_seed(self):
        matched_nodes = []
        for seed in self.seeds:
            for node in self.graph.nodes:
                if self.graph.nodes[node]['sel'] == seed.selector:
                    m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)',
                                  self.graph.nodes[node]['rec'])
                    # if m and seed.receiver == m.group('rec'):
                    matched_nodes.append(node)
        return matched_nodes

    def find_usage(self, snode, scenario):
        node_ea = int(self.graph.nodes[snode]['addr'])
        if node_ea in self.graph_indexed_by_invoke_dp:
            scenario.dps.add(snode)
            for (node_depends_on_snode, usage_type) in self.graph_indexed_by_invoke_dp[node_ea]:
                # if used as receiver, find the receiver's usage;
                # if used as parameter, find the receiver's dependency. Also usage?
                scenario.nodes.add(node_depends_on_snode)
                self.find_usage(node_depends_on_snode, scenario)

                # for succ in self.graph.succ[snode]:
                # # usage: as receiver, find the arguments dependencies if exits
                #     if node_ea in self.graph.nodes[succ]['rec']:
                #         self.find_usage()
                #         if 'args' in self.graph.nodes[succ]:
                #             pass
                #
                #     # usage: as argument, find the receiver and arguments dependencies if exits
                #     elif 'args' in self.graph.nodes[succ] and node_ea in self.graph.nodes[succ]['args']:
                #         usage.append(snode)

    def find_dependency(self, scenario, node):
        for dp_node_addr in self.node_and_dps[node]:
            for dp_node in self.graph_indexed_by_invoke_ea[dp_node_addr]:
                if dp_node in scenario.dps:
                    continue
                scenario.dps.add(dp_node)
                self.find_dependency(scenario, dp_node)

    def construct(self, scenario):
        start_node = scenario.seed_node
        self.find_usage(start_node, scenario)
        for node in scenario.nodes:
            self.find_dependency(scenario, node)
        for node in scenario.nodes:
            self.pprint_node(node)
        print '\n'

    def view(self, g):
        fp = '../results/tmp.dot'
        try:
            nx.drawing.nx_agraph.write_dot(g, fp)
        except Exception as e:
            print 'Failed to generate {}, {} '.format(fp, e)

    def pprint(self):
        for f in os.listdir(self.dir):
            trace_file = os.path.join(self.dir, f)
            print trace_file
            try:
                g = nx.drawing.nx_agraph.read_dot(trace_file)
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

    def pprint_node(self, node):
        print '-' * 80
        ea = self.graph.nodes[node]['addr']
        des = self.graph.nodes[node]['des']
        rec = self.graph.nodes[node]['rec']
        args = self.graph.nodes[node]['args'] if 'args' in self.graph.nodes[node] else None

        print hex(int(ea, 10)), des
        print 'Receiver: {} \nArguments:'.format(rec)
        if args:
            print args


class Scenario:
    def __init__(self, initial_node):
        self.seed_node = initial_node
        self.nodes = set([initial_node])
        self.dps = set([])


class Seed:
    def __init__(self, sel=None, rec=None, dt=None):
        self.receiver = rec
        self.selector = sel
        self.data_type = dt


extractor = ScenarioExtractor(seeds=[Seed(sel='identifierForVendor', rec='UIDevice')],
                              dir='../results/CsdnPlus_arm64/uidevice')
# extractor = ScenarioExtractor(seeds=[Seed(sel='generalPasteboard', rec='UIPasteboard')], dir='../results/CsdnPlus_arm64/')
# extractor.pprint()
extractor.parse_all_traces()
