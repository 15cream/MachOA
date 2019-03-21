# coding=utf-8
from tools.oc_type_parser import *
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
        self.root_dir = dir
        self.scenarios_for_mining = []

        # -------------------------------------------------------------
        # 以下数据皆为一棵执行树对应的数据 = ,  = 我知道该单独写一个执行数类

        self.eTree = None
        self.start_node = None
        self.matched_nodes = []
        self.scenario_set = []
        # 每一个地址，可能对应多个节点，因为路径敏感
        self.ea_and_nodes = dict()
        # 生产者与它的消费者们：键为生产者的地址，值为一个列表，其中每一项为一个消费者的信息元组
        self.producer_and_his_consumers = dict()
        # 消费者与其所依赖的生产者：键为消费者的节点表示，值为一个集合，集合中每一项为一个生产者信息元组
        self.consumer_and_neededProducers = dict()
        # 数据类型 与 出现的地址
        self.data_and_ptrs = dict()

    def run(self):
        for f in os.listdir(self.root_dir):
            tree_file = os.path.join(self.root_dir, f)
            # print "Now We're Parsing Execution Tree : {}".format(tree_file)
            try:
                self.parse_ET(tree_file)
                for scenario in self.scenario_set:
                    index = self.scenario_set.index(scenario)
                    scenario.view_scenario(_name="{}_{}".format(str(index), f))
                self.clear()
            except Exception as e:
                print "Failed For: {}".format(e)

    def clear(self):
        self.scenarios_for_mining.extend(self.scenario_set)
        self.eTree = None
        self.start_node = None
        self.matched_nodes = []
        self.scenario_set = []
        self.ea_and_nodes = dict()
        self.producer_and_his_consumers = dict()
        self.consumer_and_neededProducers = dict()
        self.data_and_ptrs = dict()

    def parse_ET(self, etree_file):
        """
        Give a execution tree file (inter-procedural or intra-procedural), parse this tree and extract scenarios.
        Actually, because of the path sensitivity, one tree covers several tracked_trace.
        :param etree_file:
        :return:
        """
        self.eTree = nx.drawing.nx_agraph.read_dot(etree_file)

        # 对整个执行树进行节点解析，主要记录节点之间的依赖关系
        # 在后续构建场景时，不用再上下遍历执行树/执行路径
        for node, node_data in self.eTree.nodes.items():
            if not self.start_node and node_data['des'] == 'Start':
                self.start_node = node

            ea = int(node_data['addr'])
            if ea in self.ea_and_nodes:
                self.ea_and_nodes[ea].append(node)
            else:
                self.ea_and_nodes[ea] = [node, ]
            self.consumer_and_neededProducers[node] = set()

            if 'rec' in node_data:
                m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', node_data['rec'])
                if m:
                    data_type = m.group('data_type').encode('UTF-8')
                    instance_type = m.group('instance_type').encode('UTF-8')
                    ptr = int(m.group('ptr').encode('UTF-8').strip('L'), 16)

                    # 当instance_type为RET时，当前调用的receiver 依赖于某次调用的返回值；
                    # 当为PARA时，当前调用的receiver 为传入参数；
                    # 当为IVAR时，当前调用的receiver 为ivar.

                    # 当前节点不为其所依赖的节点，当出现这种情况时通常为Start节点的传入参数？
                    if ea != ptr:
                        # 当前节点消耗了一个producer生产的值，
                        # 该producer的地址为ptr，消耗的数据类型为data_type, 该数据为RET/GEN_PARA/IVAR, 该数据用作当前节点的第０个寄存器
                        self.consumer_and_neededProducers[node].add((ptr, data_type, instance_type, 0))

                        # 反过来为生产者建立档案，为生产者的消费者们添上当前这笔
                        # 信息稍微简单一些，消费者的节点表示，以及生产的数据怎样被引用（０表示作为receiver, 2以上表示作为参数）
                        if ptr in self.producer_and_his_consumers:
                            self.producer_and_his_consumers[ptr].append((node, data_type, instance_type, 0))
                        else:
                            self.producer_and_his_consumers[ptr] = [(node, data_type, instance_type, 0), ]

                    # 记录出现的所有数据，以及地址，用于ADT类型seed的匹配
                    if data_type not in self.data_and_ptrs:
                        self.data_and_ptrs[data_type] = [ptr, ]
                    elif ptr not in self.data_and_ptrs[data_type]:
                        self.data_and_ptrs[data_type].append(ptr)

            if 'args' in node_data:
                args = node_data['args'].split('\n')[0:-1]
                for arg in args:
                    m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', arg)
                    if m:
                        data_type = m.group('data_type').encode('UTF-8')
                        instance_type = m.group('instance_type').encode('UTF-8')
                        ptr = int(m.group('ptr').encode('UTF-8').strip('L'), 16)

                        if ea != ptr:
                            # 当前节点消耗了一个producer生产的值，
                            # 该producer的地址为ptr，消耗的数据类型为data_type, 该数据为RET/GEN_PARA/IVAR, 该数据用作当前节点的第０个寄存器
                            self.consumer_and_neededProducers[node].add((ptr, data_type, instance_type, args.index(arg) + 2))

                            # ptr处instance_type类型的数据data_type，被作为node的某参数使用
                            if ptr in self.producer_and_his_consumers:
                                self.producer_and_his_consumers[ptr].append((node, data_type, instance_type, args.index(arg) + 2), )
                            else:
                                self.producer_and_his_consumers[ptr] = [(node, data_type, instance_type, args.index(arg) + 2), ]

                        if data_type not in self.data_and_ptrs:
                            self.data_and_ptrs[data_type] = [ptr, ]
                        elif ptr not in self.data_and_ptrs[data_type]:
                            self.data_and_ptrs[data_type].append(ptr)

        # ---------------------------------------------------------------------
        # 遍历执行树，获得所有路径，对每一条路径提取场景
        self.matched_nodes = self.match_seed()
        if self.start_node:
            init_trace = Trace(self.eTree, start=self.start_node)
            Trace.alive_traces.append(init_trace)
            while Trace.alive_traces:
                round = list(Trace.alive_traces)
                for trace in round:
                    if trace.alive:
                        trace.step()
            for trace in Trace.deadend_traces:
                self.parse_trace(trace)
        else:
            print "Cannot find the start node."

    def parse_trace(self, trace):
        # initial a scenario instance for each node matched seed.
        used_seed = []
        for seed in self.matched_nodes:
            if seed in trace.route and seed not in used_seed:
                scenario = Scenario(seed, trace)
                scenario.construct()
                scenario.view_scenario()
                self.scenario_set.append(scenario)

                used_seed.append(seed)
                for seed_node in self.matched_nodes:
                    if seed_node in scenario.producers or seed_node in scenario.consumers:
                        used_seed.append(seed_node)

    def match_seed(self):
        # TODO The algorithm is too rough ...
        matched_nodes = []
        for seed in self.seeds:
            if seed.data_type:
                if str_to_type(seed.data_type) in self.data_and_ptrs:  # ADT
                    for ptr in self.data_and_ptrs[str_to_type(seed.data_type)]:
                        if ptr in self.ea_and_nodes:
                            matched_nodes.extend(self.ea_and_nodes[ptr])
                for node in self.eTree.nodes:
                    if 'rec' in self.eTree.nodes[node] and self.eTree.nodes[node]['rec'] == seed.data_type:
                        matched_nodes.append(node)

            else:  # API
                for node in self.eTree.nodes:
                    if 'sel' in self.eTree.nodes[node] and self.eTree.nodes[node]['sel'] == seed.selector:
                        m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)',
                                      self.eTree.nodes[node]['rec'])
                        if m and str_to_type(seed.receiver) == m.group('data_type').encode('UTF-8'):
                            matched_nodes.append(node)
                        elif self.eTree.nodes[node]['rec'] == seed.receiver:
                            matched_nodes.append(node)
        return matched_nodes

    def pprint_node(self, node):
        if node in self.eTree.nodes:
            node_data = self.eTree.nodes[node]
            print 'NODE:', node_data['des']
            print node_data['args']


class Trace:

    alive_traces = []
    deadend_traces = []

    def __init__(self, tree, start=None, pre_existing=None):
        self.tree = tree
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
        out_edges = self.tree.out_edges(self.route[-1])
        if len(out_edges) == 0:
            # print "Trace terminated at {}.".format(self.route[-1])
            self.terminate()
        elif len(out_edges) == 1:
            self.route.append(list(out_edges)[0][-1])
        elif len(out_edges) > 1:
            for edge in list(out_edges)[1:]:
                forked_trace = Trace(self.tree, pre_existing=copy.deepcopy(self.route))
                forked_trace.route.append(edge[-1])
                Trace.alive_traces.append(forked_trace)
            self.route.append(list(out_edges)[0][-1])
        else:
            print '??? WHY ???'


class Scenario:
    def __init__(self, initial_node, trace):
        self.extractor = ScenarioExtractor.task
        self.trace = trace
        self.etree = trace.tree
        self.seed_node = initial_node
        self.consumers = set([initial_node])
        self.producers = set([])
        # 场景本质上是基于数据依赖关联的DAG
        self.dpg = nx.DiGraph()
        # 从原路径中提取出场景中的节点，按原排序构成子序列
        self.sub_trace = dict()

    def construct(self):
        # self.add_node(self.seed_node)
        # 根据seed，向下查找使用，并记录所有使用节点；关系可传递
        self.find_usage(self.seed_node)
        # 对已经存在场景中的节点，向上查找依赖；关系可传递（但这些非seed节点，暂时不用查找它们的使用）
        for node in self.consumers:
            self.find_dependency(node)

    def find_usage(self, node):

        node_ea = int(self.etree.nodes[node]['addr'])
        # 查看该节点是否有被作为producer的记录
        if node_ea in self.extractor.producer_and_his_consumers:
            self.producers.add(node)
            for (consumer, data, instance_type, usage_type) in self.extractor.producer_and_his_consumers[node_ea]:
                # 当usage_type为０时，表示该数据曾被当做其他调用的接受者
                # 当usage_type为２及以上时，表示该数据曾被当做其他调用的参数
                # 其余两项表示：producer产生的instance_type类型的data被该consumer使用
                if consumer in self.trace.route:
                    self.consumers.add(consumer)
                    # 由于生产者除了是方法调用外
                    if instance_type != 'RET':
                        producer_node = self.add_node(node, data=data)
                    else:
                        producer_node = self.add_node(node)
                    consumer_node = self.add_node(consumer)
                    # 这里边的label用于表示上一个调用节点的返回值/上一个数据节点在下一个节点中是如何被使用的
                    self.dpg.add_edge(producer_node, consumer_node, label=usage_type)
                    self.find_usage(consumer)

    def find_dependency(self, consumer):
        for (producer_ea, data, instance_type, dp_type) in self.extractor.consumer_and_neededProducers[consumer]:
            # TODO producer may come from ivar segment
            if producer_ea in self.extractor.ea_and_nodes:
                for producer in self.extractor.ea_and_nodes[producer_ea]:
                    if producer in self.trace.route:
                        if producer in self.producers:
                            continue
                        self.producers.add(producer)
                        if instance_type != 'RET':
                            producer_node = self.add_node(producer, data=data)
                        else:
                            producer_node = self.add_node(producer)
                        consumer_node = self.add_node(consumer)
                        self.dpg.add_edge(producer_node, consumer_node, label=dp_type)
                        self.find_dependency(producer)

    def standardization(self, node_dict, data=None):
        """
        If the node is 'Start', the node should be rule other than invoke.
        :param data:
        :param node_dict:
        :param dp_type: if 'Start', the exact rule position.
        :return:
        """
        if data:
            return type_to_str(data)
        if node_dict['des'] == u'Start':
            return node_dict['context_name']
        if '#' in node_dict['des']:
           return re.sub(r'#[0-9]+', '', node_dict['des'])

        return node_dict['des']

    def add_node(self, ori_node, data=None):
        """
        Add one node to the scenario's dpg.
        :param data:
        :param ori_node: the original representation in execution tree.
        :return: new representation.
        """
        node_dict = self.etree.nodes[ori_node]
        node = self.standardization(node_dict, data=data)
        if node not in self.dpg.nodes:
            self.dpg.add_node(node, des=node_dict)
            self.sub_trace[self.trace.route.index(ori_node)] = node
        else:
            pass
        return node

    def view_scenario(self, _name=None):
        # sub_graph = nx.subgraph(self.trace.graph, self.consumers | self.producers)
        name = _name if _name else 'tmp'
        # for index, des in sorted(self.sub_trace.items(), key=lambda item: item[0]):
        #     print index, des
        # print '-' * 80

        fp = '../../results/ScenarioTest/total_scenarios/{}.dot'.format(name)
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
#                               root_dir='../results/CsdnPlus_arm64/uidevice2')
# extractor = ScenarioExtractor(seeds=[Seed(sel='generalPasteboard', rec='UIPasteboard')],
#                               root_dir='../results/CsdnPlus_arm64/')
# extractor = ScenarioExtractor(seeds=[Seed(rec='UIDevice', sel='identifierForVendor')],
#                               root_dir='../results/DoubanRadio_arm64/')
# extractor = ScenarioExtractor(seeds=[Seed(sel='alloc', rec='CLLocationManager')],
#                               root_dir='../results/ScenarioTest/ToGoProject/')

extractor = ScenarioExtractor(dir='/home/gjy/Desktop/LogBOok/01/第五次实验/')
extractor.run()