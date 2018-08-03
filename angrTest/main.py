__author__ = 'gjy'
import angr
import angr.engines.successors
import angr.sim_state
from cle.backends.macho.binding import BindingHelper
from Data.class_o import class_o
from Data.function import Function
from Data.stubs import *
import time
import angr.sim_options as option
from types import *

class Analyzer:

    def __init__(self, binary, database=None, store=None, visualize=None):
        self.p = angr.Project(binary)
        self.loader = self.p.loader
        self.macho = self.loader.main_object
        self.current_f = None
        self.next_func_addr = None
        self.init_state = None  # memeory initialized
        self.manager = None
        self.database = database
        self.store = store
        self.visualize = visualize

        MachO.pd = self.pd = MachO(self.macho, self.loader, self.p, self)
        self.data_init()

    def data_init(self):
        self.init_state = self.p.factory.blank_state()
        self.init_state.options.add(option.LAZY_SOLVES)
        bh = BindingHelper(self.macho)
        bh.do_normal_bind(self.macho.rebase_blob)
        bh.do_normal_bind(self.macho.binding_blob)
        bh.do_lazy_bind(self.macho.lazy_binding_blob)
        self.pd.build_classdata(self.init_state, packed=self.database)
        Function.build_meth_list()
        hook_stubs(self.init_state)

    def analyze_function(self, start_addr=None, name=None):
        if name:
            start_addr = Function.retrieve_f(name=name, ret=0b100)[0]

        st = self.init_state.copy()
        st.regs.ip = start_addr
        self.current_f = Function(start_addr, st)
        self.current_f.init_state()
        self.next_func_addr = Function.meth_list[Function.meth_list.index(start_addr) + 1]

        st.inspect.b('exit', when=angr.BP_BEFORE, action=branch)
        self.manager = sm = self.p.factory.simgr(st)
        # sm.run()
        while sm.active:
            sm.step()
        print "Ret Value: {}".format(self.current_f.retVal)
        if self.store:
            self.current_f.dump()
        self.current_f.print_call_string()


    def analyze_class(self, classref=None, classname=None):
        class_obj = class_o.retrieve(classref=classref, classname=classname)
        for meth in class_obj.instance_meths:
            self.analyze_function(start_addr=meth)
        for meth in class_obj.class_meths:
            self.analyze_function(start_addr=meth)

    def analyze_bin(self):
        for f in class_o.functions:
            analyzer.analyze_function(start_addr=f)
            # print "Ret Value: {}".format(analyzer.current_f.retVal)

print time.strftime("-START-%Y-%m-%d %H:%M:%S", time.localtime())

analyzer = Analyzer('../samples/ToGoProject', database=True, store=True, visualize=False)
# analyzer.analyze_class(classname='TGHttpManager')
# analyzer.analyze_class(classref=0x1000c39d4)
analyzer.analyze_function(0x1000c43d4)

print time.strftime("-END-%Y-%m-%d %H:%M:%S", time.localtime())



# analyzer.analyze_function(start_addr=0x1000C232C)
# analyzer.analyze_function(name="+[TGHttpManager queryStringFromParameters:]")
# analyzer.analyze_function(0x100050110)
# analyzer.analyze_function(0x100005C30)
# analyzer.analyze_function(0x1003CC798)
# analyzer.analyze_function(0x10000D0C0)
# analyzer.analyze_function(0x1000C39D4)
# analyzer.analyze_function(0x1000C46B4)


