__author__ = 'gjy'
import angr
import angr.engines.successors
import angr.sim_state
from cle.backends.macho.binding import BindingHelper
from Data.class_o import class_o
from Data.function import Function
from Data.stubs import *


class Analyzer:

    def __init__(self, binary):
        self.p = angr.Project(binary)
        self.loader = self.p.loader
        self.macho = self.loader.main_object
        MachO.pd = self.pd = MachO(self.macho, self.loader, self.p, self)

        self.current_f = None
        self.init_state = None  # memeory initialized

    def data_init(self):
        self.init_state = self.p.factory.blank_state()
        bh = BindingHelper(self.macho)
        bh.do_normal_bind(self.macho.rebase_blob)
        bh.do_normal_bind(self.macho.binding_blob)
        bh.do_lazy_bind(self.macho.lazy_binding_blob)
        self.pd.build_classdata(self.init_state)
        hook_stubs(self.init_state)


    def analyze_function(self, start_addr):
        st = self.init_state.copy()
        st.regs.ip = start_addr
        # st.options.add(option.LAZY_SOLVES)
        self.current_f = Function(start_addr, st)

        if start_addr in class_o.functions:
            meth_info = class_o.functions[start_addr]
            print "Analyze method {}. ".format(meth_info[0])
            classref = meth_info[1].classref_addr
            bv = st.solver.BVV(classref, 64)
            st.regs.x0 = bv

        sm = self.p.factory.simgr(st)
        # looplimiter = angr.exploration_techniques.LoopSeer(bound=1)
        # sm.use_technique(looplimiter)
        # while sm.active:
        #     for s in sm.active:
        #         s.inspect.b('exit', when=angr.BP_BEFORE, condition=bc.ret_cond, action=bc.get_retval)
        #     sm.step()
        sm.run()

        self.current_f.print_call_string()
        print '---------------------------------'

    def analyze_class(self, classref):
        for meth in class_o.classrefs[classref].instance_meths:
            imp = meth[0]
            methname = meth[1]
            self.analyze_function(imp)

analyzer = Analyzer('../samples/ToGoProject')
analyzer.data_init()
# analyzer.analyze_function(0x1000C232C)
analyzer.analyze_function(0x100050110)
# analyzer.analyze_function(0x100005C30)
# analyzer.analyze_function(0x1003CC798)
# analyzer.analyze_function(0x1000C39D4)
# analyzer.analyze_function(0x1000C46B4)

