import os
import re
import networkx as nx
import copy
import sys
reload(sys)
sys.setdefaultencoding('utf-8')


class ScenarioExtractor:

    task = None

    def __init__(self, seeds=None, dir=None):
        ScenarioExtractor.task = self
        self.seeds = seeds
        self.matched_nodes = []
        self.dir = dir
        self.graph = None
        self.graph_indexed_by_invoke_ea = dict()  # each ea may have several nodes in different traces.
        self.node_and_his_usage = dict()  # key:node(ptr only) value: set of nodes use this node
        self.node_and_his_dps = dict()  # key:node value: set of nodes(ptr only) this node relies on
        self.scenario_set = []

    def run(self):
        for f in os.listdir(self.dir):
            cfg_file = os.path.join(self.dir, f)
            print "Now we're parsing cfg_file : {}".format(cfg_file)
            try:
                self.parse_cfg(cfg_file)
                self.clear()
            except Exception as e:
                print "Failed for {}".format(e)
        print 'END HERE.'
        for scenario in self.scenario_set:
            index = self.scenario_set.index(scenario)
            scenario.view_scenario(_name=str(index))

    def clear(self):
        self.graph = None
        self.graph_indexed_by_invoke_ea = dict()
        self.node_and_his_usage = dict()
        self.node_and_his_dps = dict()

    def parse_cfg(self, cfg_file):
        """
        Give a call-graph file (inter-procedural or intra-procedural), parse this cfg and extract scenarios.
        Actually, because of the path sensitivity, one cfg covers several traces.
        :param cfg_file:
        :return:
        """
        self.graph = nx.drawing.nx_agraph.read_dot(cfg_file)
        self.matched_nodes = self.match_seed()

        for node, node_data in self.graph.nodes.items():
            self.node_and_his_dps[node] = set()
            ea = int(node_data['addr'])
            if ea in self.graph_indexed_by_invoke_ea:
                self.graph_indexed_by_invoke_ea[ea].append(node)
            else:
                self.graph_indexed_by_invoke_ea[ea] = [node, ]

            if 'rec' in node_data:
                m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', node_data['rec'])
                if m:
                    ptr = int(m.group('ptr').encode('UTF-8').strip('L'), 16)
                    if ptr in self.node_and_his_usage:
                        self.node_and_his_usage[ptr].append((node, 0))
                    else:
                        self.node_and_his_usage[ptr] = [(node, 0), ]
                    # self.node_and_his_dps[node].add(ptr)
                    self.node_and_his_dps[node].add((ptr, 0))

            if 'args' in node_data:
                args = node_data['args'].split('\n')[0:-1]
                for arg in args:
                    m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', arg)
                    if m:
                        ptr = int(m.group('ptr').encode('UTF-8').strip('L'), 16)
                        if ptr in self.node_and_his_usage:
                            self.node_and_his_usage[ptr].append((node, args.index(arg)+2))
                        else:
                            self.node_and_his_usage[ptr] = [(node, args.index(arg)+2), ]
                        # self.node_and_his_dps[node].add(ptr)
                        self.node_and_his_dps[node].add((ptr, args.index(arg)+2))

        # parse traces >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.
        start_node = None
        for node in self.graph.nodes:
            if self.graph.nodes[node]['des'] == 'Start':
                start_node = node
                break
        if start_node:
            Trace.alive_traces.append(Trace(self.graph, start=start_node))
            while Trace.alive_traces:
                round = list(Trace.alive_traces)
                for trace in round:
                    if trace.alive:
                        trace.step()
            for trace in Trace.deadend_traces:
                self.parse_trace(trace)
            print 'End here.'
        else:
            print "Cannot find the start node."

    def parse_trace(self, trace):
        # initial scenarios for each node matched seed.
        for seed in self.matched_nodes:
            if seed in trace.route:
                scenario = Scenario(seed, trace)
                scenario.construct()
                scenario.view_scenario()
                self.scenario_set.append(scenario)

    def match_seed(self):
        # TODO The algorithm is too rough ...
        matched_nodes = []
        for seed in self.seeds:
            for node in self.graph.nodes:
                if 'sel' in self.graph.nodes[node] and self.graph.nodes[node]['sel'] == seed.selector:
                    m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)',
                                  self.graph.nodes[node]['rec'])
                    # if m and seed.receiver == m.group('rec'):
                    matched_nodes.append(node)
        return matched_nodes

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


class Trace:

    alive_traces = []
    deadend_traces = []

    def __init__(self, graph, start=None, pre_existing=None):
        self.graph = graph
        if start:
            self.route = [start, ]
        else:
            self.route = pre_existing
        self.alive = True

    def terminate(self):
        self.alive = False
        Trace.alive_traces.remove(self)
        Trace.deadend_traces.append(self)

    def step(self):
        out_edges = self.graph.out_edges(self.route[-1])
        if len(out_edges) == 0:
            print "Trace terminated at {}.".format(self.route[-1])
            self.terminate()
        elif len(out_edges) == 1:
            self.route.append(list(out_edges)[0][-1])
        elif len(out_edges) == 2:
            forked_trace = Trace(self.graph, pre_existing=copy.deepcopy(self.route))
            forked_trace.route.append(list(out_edges)[1][-1])
            Trace.alive_traces.append(forked_trace)
            self.route.append(list(out_edges)[0][-1])
        else:
            print '??? WHY ???'


class Scenario:
    def __init__(self, initial_node, trace):
        self.dpg = nx.DiGraph()
        self.extractor = ScenarioExtractor.task
        self.trace = trace
        self.cfg = trace.graph
        self.seed_node = initial_node
        self.usages = set([initial_node])
        self.dps = set([])

    def add_node(self, ori_node):
        node_dict = self.cfg.nodes[ori_node]
        node = "{}:{}".format(node_dict['addr'], node_dict['des'])
        if node not in self.dpg.nodes:
            self.dpg.add_node(node, des=node_dict['des'])
        else:
            pass
        return node

    def construct(self):
        self.add_node(self.seed_node)
        self.find_usage(self.seed_node)  # find nodes used the seed.
        for node in self.usages:
            self.find_dependency(node)

    def find_usage(self, producer):
        graph = self.trace.graph
        node_ea = int(graph.nodes[producer]['addr'])
        if node_ea in self.extractor.node_and_his_usage:
            self.dps.add(producer)
            for (usage, usage_type) in self.extractor.node_and_his_usage[node_ea]:
                # if used as receiver, find the receiver's usage;
                # if used as parameter, find the receiver's dependency. Also usage?
                if usage in self.trace.route:
                    self.usages.add(usage)
                    producer_node = self.add_node(producer)
                    consumer_node = self.add_node(usage)
                    self.dpg.add_edge(producer_node, consumer_node, label=usage_type)
                    self.find_usage(usage)

    def find_dependency(self, consumer):
        for (producer_ea, dp_type) in self.extractor.node_and_his_dps[consumer]:
            for dp_node in self.extractor.graph_indexed_by_invoke_ea[producer_ea]:
                if dp_node in self.trace.route:
                    if dp_node in self.dps:
                        continue
                    self.dps.add(dp_node)
                    producer_node = self.add_node(dp_node)
                    consumer_node = self.add_node(consumer)
                    self.dpg.add_edge(producer_node, consumer_node, label=dp_type)
                    self.find_dependency(dp_node)

    def view_scenario(self, _name=None):
        sub_graph = nx.subgraph(self.trace.graph, self.usages | self.dps)
        name = _name if _name else 'tmp'
        fp = '../results/DoubanRadio_arm64/scenarios/{}.dot'.format(name)
        try:
            nx.drawing.nx_agraph.write_dot(self.dpg, fp)
        except Exception as e:
            print 'Failed to generate {}, {} '.format(fp, e)


class Seed:
    def __init__(self, sel=None, rec=None, dt=None):
        self.receiver = rec
        self.selector = sel
        self.data_type = dt


# extractor = ScenarioExtractor(seeds=[Seed(sel='identifierForVendor', rec='UIDevice')],
#                               dir='../results/CsdnPlus_arm64/uidevice2')
# extractor = ScenarioExtractor(seeds=[Seed(sel='generalPasteboard', rec='UIPasteboard')],
#                               dir='../results/CsdnPlus_arm64/')
extractor = ScenarioExtractor(seeds=[Seed(rec='UIDevice', sel='identifierForVendor')],
                              dir='../results/DoubanRadio_arm64/')
# extractor.pprint()
extractor.run()