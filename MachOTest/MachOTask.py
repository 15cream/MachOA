__author__ = 'gjy'
import time

import angr.engines.successors
import angr.sim_state
from cle.backends.macho.binding import BindingHelper
import ConfigParser

from Data.class_o import class_o
from Data.function import Function
from Data.func import Func
from angrutils import *
from Data.stubs import *
from tools.utils import *
from tools.b_callbacks import *
from tools.drawCG import CG


class ATask:

    currentTask = None

    def __init__(self, binary, store=None, visualize=None):
        self.p = angr.Project(binary)
        self.loader = self.p.loader
        self.macho = self.loader.main_object
        self.current_f = None
        self.next_func_addr = None
        self.init_state = None  # memeory initialized
        self.simgr = None
        self.store = store
        self.visualize = visualize
        self.configs = None
        self.pd = MachO(self.macho, self.loader, self.p, self)
        self.pre_process()
        self.checked = check_files_in_dir(self.configs.get('PATH', 'dds'))
        self.db = "{}{}.pkl".format(self.configs.get('PATH', 'dbs'), self.macho.provides)
        self.cg = CG()

        self.class_blacklist = []
        self.meth_blacklist = []

    def config(self):
        config = ConfigParser.RawConfigParser()
        config.read('/home/gjy/Desktop/MachOA/config/config')
        xml_path = "{}{}".format(config.get('PATH', 'xmls'), self.macho.provides)
        dd_path = "{}{}".format(config.get('PATH', 'dds'), self.macho.provides)
        result_path = "{}{}".format(config.get('PATH', 'results'), self.macho.provides)
        if not os.path.exists(xml_path):
            os.mkdir(xml_path)
        if not os.path.exists(dd_path):
            os.mkdir(dd_path)
        if not os.path.exists(result_path):
            os.mkdir(result_path)
        self.configs = config

    def pre_process(self):
        self.config()
        self.init_state = self.p.factory.blank_state()
        bh = BindingHelper(self.macho)
        bh.do_normal_bind(self.macho.rebase_blob)
        bh.do_normal_bind(self.macho.binding_blob)
        bh.do_lazy_bind(self.macho.lazy_binding_blob)
        self.pd.build_classdata(self.init_state)
        Function.build_meth_list(self.pd)
        hook_stubs(self.init_state)

    def analyze_function(self, start_addr=None, name=None):
        self.cg = CG()
        if name:
            start_addr = Function.retrieve_f(name=name)['imp']
        if start_addr in self.meth_blacklist:
            return
        st = self.init_state.copy()
        # self.cg.add_simple_node(start_addr, 'Start', st)
        # st.regs.ip = start_addr
        # self.current_f = Function(start_addr, st, self)
        # try:
        #     self.next_func_addr = self.macho.lc_function_starts[self.macho.lc_function_starts.index(start_addr) + 1]
        # except IndexError:
        #     self.next_func_addr = None

        st.inspect.b('exit', when=angr.BP_BEFORE, action=branch)
        st.inspect.b('address_concretization', when=angr.BP_AFTER, action=mem_resolve)
        # st.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_read_resolve)


        # self.simgr = sm = self.p.factory.simgr(st)
        # while sm.active:
        #     sm.step()
        # if self.store:
        #     # self.current_f.dump()
        #     self.cg.view()

        f = Func(start_addr, self.macho, self, st)
        f.init_regs()
        f.analyze()
        self.cg.view()

        # cfg = self.p.analyses.CFGAccurate(keep_state=True, starts=[start_addr, ], initial_state=st, call_depth=2,
        #                               context_sensitivity_level=3)
        # plot_cfg(cfg, "ais4_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)

    def analyze_bin(self):
        for ref in class_o.classes_indexed_by_ref.keys():
            if ref in self.class_blacklist:
                continue
            self.analyze_class_dds(classref=ref)

    def analyze_class_dds(self, classref=None, classname=None):
        class_obj = class_o.retrieve(classref=classref, classname=classname)
        if class_obj.imported:
            return
        if class_obj.name in self.checked:
            return
        fp = "{}{}/{}.txt".format(self.configs.get('PATH', 'dds'), self.macho.provides, class_obj.name)
        with open(fp, 'w') as f:
            for meth in class_obj.instance_meths.extend(class_obj.class_meths):
                if meth in self.meth_blacklist:
                    continue
                self.analyze_function(start_addr=meth)
                f.write("\n---------{}----------\n".format(self.current_f.name))
                f.write("\n".join(self.current_f.dds))

    def analyze_class(self, classref=None, classname=None):
        class_obj = class_o.retrieve(classref=classref, classname=classname)
        if class_obj.imported:
            return
        if class_obj.name in self.checked:
            return
        for meth in class_obj.class_meths:
            if meth in self.meth_blacklist:
                continue
            self.analyze_function(start_addr=meth)
        for meth in class_obj.instance_meths:
            if meth in self.meth_blacklist:
                continue
            self.analyze_function(start_addr=meth)


print time.strftime("-START-%Y-%m-%d %H:%M:%S", time.localtime())





