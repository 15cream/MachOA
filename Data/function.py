__author__ = 'gjy'

from Data.invokenode import InvokeNode
import re
from class_o import class_o
import xml.etree.ElementTree as ET

class Function:

    meth_list = []
    meth_data = dict()
    function_symbols = dict()
    callgraph = None

    def __init__(self, addr, state):
        self.name = Function.meth_data[addr]['name']
        self.start = addr
        self.end = None
        self.invokes = dict()  # state_addr, invoke_node
        self.state = state
        self.start_node = None
        self.build_start_node()
        self.retVal = []

    @staticmethod
    def build_meth_list():
        Function.meth_list = sorted(class_o.classes_indexed_by_meth.keys())
        for meth_imp in Function.meth_list:
            if meth_imp not in Function.meth_data:
                Function.meth_data[meth_imp] = {'name':class_o.classes_indexed_by_meth[meth_imp][0],
                                                'class':class_o.classes_indexed_by_meth[meth_imp][1]}
            name = class_o.classes_indexed_by_meth[meth_imp][0]
            if name not in Function.function_symbols:
                Function.function_symbols[name] = meth_imp

    @staticmethod
    def retrieve_f(name=None, imp=None, ret=None):
        # ret=the information you ask for. 3 bits are used to specify specified info
        # 0b111 --> imp ; completed name; meth type. 1 for yes, 0 for no
        if name:
            m = re.search('(?P<type>[-+]?)\[(?P<receiver>.+?) (?P<selector>[\w:]+)\]', name)
            if m:
                type = m.group('type')
                receiver = m.group('receiver')
                if receiver not in class_o.classes_indexed_by_name:
                    return None
                selector = m.group('selector')
            else:
                print "NOT FOUND" + name
                return None

        results = []
        if name:
            for s, imp in Function.function_symbols.items():
                if name in s:
                    if ret and 0b100:
                        results.append(imp)
                    if ret and 0b010:
                        results.append(s)
                    if ret and 0b001:
                        results.append(s[0])  # should change to meth_type, such as v40@0:8@16@24@32
                    return results

    def init_state(self):
        if self.start in Function.meth_list:
            meth_data = Function.meth_data[self.start]
            print " * * * * * * * * * * * Analyze method {} at {}  * * * * * * * * * * * ".format(meth_data['name'], hex(self.start))
            class_data = meth_data['class']
            if self.start in class_data.instance_meths:
                classname = meth_data['class'].name
                self.state.regs.x0 = self.state.solver.BVS(classname + "_instance", 64)
            else:
                classref = meth_data['class'].classref_addr
                self.state.regs.x0 = self.state.solver.BVV(classref, 64)

    def build_start_node(self):
        start_node = InvokeNode(self.start)
        start_node.set_description("Start")
        self.start_node = start_node
        self.invokes[self.state.history] = start_node

    def resolve_dependency(self, receiver):
        match = re.search('ret_from_(?P<addr>\w+?)L_.*', receiver)
        if match:
            d_addr = int(match.group('addr'), 16)
            for node in self.invokes.values():
                if d_addr == node.addr:
                    return node
        else:
            return None

    def insert_invoke(self, state, ins_addr, selector, receiver):
        node = InvokeNode(ins_addr)
        d = '[' + receiver + ' ' + selector + ']'
        argc = selector.count(':')
        args = []
        for c in range(0, argc):
            reg_name = 'x{}'.format(c + 2)
            args.append(str(state.solver.eval(state.regs.get(reg_name))))

        meth_info = Function.retrieve_f(name=d, ret=0b110)
        if meth_info:
            d = "{} ({}) args:{}".format(meth_info[1], hex(meth_info[0]), args)

        node.set_deps('receiver', self.resolve_dependency(receiver))
        node.set_description(d)
        history = state.history
        if history not in self.invokes:
            self.invokes[history] = node
        while True:
            history = history.parent
            if history in self.invokes:
                self.invokes[history].add_child(node)
                break

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
        f = ET.Element('FUNCTION')
        f.set('name', self.name)
        f.set('address', hex(self.start))

        # self.dump_node(f, self.start_node)
        for node in self.invokes.values():
            f.append(node.xmlNode())
        f = ET.ElementTree(f)
        f.write("../xmls/{}.xml".format(self.name))

    def dump_node(self, f_node, invoke_node):
        f_node.append(invoke_node.xmlNode())
        for next in invoke_node.next():
            self.dump_node(f_node, next)


