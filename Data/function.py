# coding=utf-8
from binary import MachO
from Data.invokenode import InvokeNode
import re
from class_o import class_o
import xml.etree.ElementTree as ET
import networkx as nx
import sys
reload(sys)
sys.setdefaultencoding('utf8')

C_FUNC_ARGC = 0

class Function:

    meth_list = []
    meth_data = dict()
    function_symbols = dict()
    callgraph = None
    subroutines = []

    def __init__(self, addr, state, analyzer):
        self.G = nx.DiGraph()
        self.analyzer = analyzer
        self.name = Function.meth_data[addr]['name']
        self.start = addr
        self.end = None
        self.type = 'sub' if not Function.meth_data[addr]['class'] else "meth"
        self.invokes = dict()  # state_addr, invoke_node
        self.state = state
        self.start_node = self.build_start_node()
        self.retVal = []
        self.dds = []
        self.init_state()


    @staticmethod
    def build_meth_list(pd):

        Function.meth_list = pd.macho.lc_function_starts
        for meth_imp in Function.meth_list:
            if meth_imp in class_o.classes_indexed_by_meth:
                if meth_imp not in Function.meth_data:
                    Function.meth_data[meth_imp] = {'name':class_o.classes_indexed_by_meth[meth_imp][0],
                                                    'class':class_o.classes_indexed_by_meth[meth_imp][1]}
                name = class_o.classes_indexed_by_meth[meth_imp][0]
            else:
                # subroutine
                name = 'sub_' + str(hex(meth_imp))
                if meth_imp not in Function.meth_data:
                    Function.meth_data[meth_imp] = {'name': name,
                                                    'class': None}
                if meth_imp not in Function.subroutines:
                    Function.subroutines.append(meth_imp)

            if name not in Function.function_symbols:
                Function.function_symbols[name] = meth_imp



    @staticmethod
    def retrieve_f(name=None, imp=None, ret=None):
        # ret=the information you ask for. bits are used to specify specified info
        # 0b11111 --> receiver; selector; imp ; completed name; meth type. 1 for yes, 0 for no
        if name:
            m = re.search('(?P<type>[-+]?)\[(?P<receiver>\S+?) (?P<selector>[\w:]+)\]', name)
            if m:
                type = m.group('type')
                receiver = m.group('receiver')
                if receiver not in class_o.classes_indexed_by_name:
                    return None
                selector = m.group('selector')
                if ret & 0b10000 and receiver:
                    return receiver
                if ret & 0b1000 and selector:
                    return selector

        results = []
        if name:
            for s, imp in Function.function_symbols.items():
                if name in s:
                    if ret & 0b100:
                        results.append(imp)
                    if ret & 0b010:
                        results.append(s)
                    if ret & 0b001:
                        results.append(s[0])  # should change to meth_type, such as v40@0:8@16@24@32
                    return results

    def init_state(self):
        if self.start in Function.meth_list:
            meth_data = Function.meth_data[self.start]
            print " * * * * * * * * * * * Analyze method {} at {}  * * * * * * * * * * * ".format(meth_data['name'], hex(self.start))
            class_data = meth_data['class']
            if class_data:
                if self.start in class_data.instance_meths:
                    classname = meth_data['class'].name
                    self.state.regs.x0 = self.state.solver.BVS(classname + "_instance", 64)
                else:
                    classref = meth_data['class'].classref_addr
                    self.state.regs.x0 = self.state.solver.BVV(classref, 64)
                argc = meth_data['name'].count(':')
                for i in range(0, argc):
                    reg = 'x'+str(i+2)
                    newval = self.state.solver.BVS("p" + str(i), 64)
                    self.state.registers.store(reg, newval)
            else:
                # subroutine
                pass

    def build_start_node(self):
        start_node = InvokeNode(self.start)
        if self.type == 'meth':
            start_node.set_receiver(self.retrieve_f(self.name, ret=0b10000))
            start_node.set_selector(self.retrieve_f(self.name, ret=0b1000))
        start_node.set_description(self.name)
        self.invokes[self.state.history] = start_node
        self.G.add_node(hex(start_node.addr), label=start_node.show_description(detailed=True), constraints=self.state.solver.constraints)
        return start_node

    def resolve_dependency(self, receiver):
        match = re.search('RetFrom_(?P<addr>\w+?)L_.*', receiver)
        if match:
            d_addr = int(match.group('addr'), 16)
            for node in self.invokes.values():
                if d_addr == node.addr:
                    return node
        else:
            return None

    def insert_invoke(self, state, ins_addr, selector=None, receiver=None, symbol=None):
        node = InvokeNode(ins_addr)
        for f in sorted(self.analyzer.macho.lc_function_starts):
            if ins_addr < f:
                break
        node.context = self.analyzer.macho.lc_function_starts[self.analyzer.macho.lc_function_starts.index(f) - 1]

        if symbol:
            argc = C_FUNC_ARGC
            args = []
            for i in range(0, argc):
                reg_name = 'x{}'.format(i)
                reg_val = MachO.resolve_reg(state, state.regs.get(reg_name))
                args.append(reg_val)
            node.set_args(args)
            node.set_description(symbol)
        else:
            node.set_receiver(receiver)
            node.set_selector(selector)
            node.set_deps('receiver', self.resolve_dependency(receiver))
            argc = selector.count(':')
            args = []
            for c in range(0, argc):
                reg_name = 'x{}'.format(c + 2)
                reg_val = MachO.pd.resolve_reg(state, state.regs.get(reg_name))
                args.append(reg_val)
            node.set_args(args)

            d = '[' + receiver + ' ' + selector + ']'
            meth_info = Function.retrieve_f(name=d, ret=0b10)
            if meth_info:
                d = meth_info[0]
            node.set_description(d)

        history = state.history
        if history not in self.invokes:
            self.invokes[history] = node
            if state.solver.constraints:
                for c in state.solver.constraints:
                    node.constraints.append(str(c).replace('<', '').replace('>', ''))
        while True:
            history = history.parent
            if history in self.invokes:
                color = 'red' if self.invokes[history].context != node.context else 'green'
                self.invokes[history].add_child(node)
                # src = hex(self.invokes[history].addr)
                # des = hex(node.addr)
                # self.G.add_node(des, label=node.show_description(detailed=True), constraints=state.solver.constraints)
                # cons_addition = []
                # for c in self.G.nodes[des]['constraints']:
                #     if c not in self.G.nodes[src]['constraints']:
                #         cons_addition.append(str(c))
                #
                # self.G.add_edge(src, des, color=color)
                src = "{} {}".format(hex(self.invokes[history].addr),
                                     self.invokes[history].show_description(detailed=True))
                des = "{} {}".format(hex(node.addr), node.show_description(detailed=True))
                self.G.add_node(des, label=hex(node.addr))
                self.G.add_edge(src, des, label='\n'.join(self.find_constrint_addtion(self.invokes[history], node)), color=color)
                break

    def find_constrint_addtion(self, src, des):
        constraints = []
        for c in des.constraints:
            if c not in src.constraints:
                constraints.append(c)
        return constraints

    def godown(self, node, callstring):
        callstring.append(node)
        if node.next:
            for child in node.next:
                self.godown(child, callstring)
        else:
            for c in callstring:
                print str(hex(c.addr)), c.description,  '->',
            print 'End'
        callstring.pop()

    def print_call_string(self):
        callstring = []
        node = self.start_node
        self.godown(node, callstring)

    def setRetVal(self, val):
        self.retVal.append(val)

    def dump(self):
        try:
            # self.resolve_dependencies()
            # f = ET.Element('FUNCTION')
            # f.set('name', self.name)
            # f.set('address', hex(self.start))
            #
            # # self.dump_node(f, self.start_node)
            # for node in self.invokes.values():
            #     f.append(node.xmlNode())
            # f = ET.ElementTree(f)
            # output = "{}{}/{}.xml".format(self.analyzer.configs.get('PATH', 'xmls'), self.analyzer.macho.provides, self.name)
            # f.write(output)
            # cg = CallGraph(output)
            # cg.build()
            # cg.output('/home/gjy/Desktop/MachOA/visualize/cgs/rsa.pdf')
            # print "\n".join(self.dds)
            # nx.drawing.nx_agraph.view_pygraphviz(self.G)
            nx.drawing.nx_agraph.write_dot(self.G, 'callG.dot')
            nx.draw(self.G, with_labels=True)
        except UnicodeDecodeError:
            print "UnicodeDecodeError at {}".format(hex(self.start))

    def dump_node(self, f_node, invoke_node):
        f_node.append(invoke_node.xmlNode())
        for next in invoke_node.next():
            self.dump_node(f_node, next)

    def resolve_dependencies(self):
        for node in self.invokes.values():
            self.dds.append(hex(node.addr) + node.get_expr())






