__author__ = 'gjy'
import time

import angr.engines.successors
import angr.sim_state
from cle.backends.macho.binding import BindingHelper
import angr.sim_options as option
from angrutils import *
import ConfigParser
import os

from Data.class_o import class_o
from Data.function import Function
from Data.stubs import *
from tools.utils import *
from tools.b_callbacks import *


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
        # ATask.analyzer = self
        self.data_init()
        self.checked = check_files_in_dir(self.configs.get('PATH', 'dds'))
        self.db = "{}{}.pkl".format(self.configs.get('PATH', 'dbs'), self.macho.provides)

        self.class_blacklist = [0x100D5C558, 0x0100D5F5E8, 0x100D5F028, 0X100D5C588, 0X0100D5EB30]
        self.meth_blacklist = [0x1003b8900, 0x1003a4a80, 0x1003ceb30, 0x1000b65fc, 0x1003a7fc0, 0x10009002c,
                               0x1003e2a8c, 0x100698310, 0x1000957a0, 0x100097b50]

    def config(self):
        config = ConfigParser.RawConfigParser()
        config.read('/home/gjy/Desktop/MachOA/config/config')
        xml_path = "{}{}".format(config.get('PATH', 'xmls'), self.macho.provides)
        dd_path = "{}{}".format(config.get('PATH', 'dds'), self.macho.provides)
        if not os.path.exists(xml_path):
            os.mkdir(xml_path)
        if not os.path.exists(dd_path):
            os.mkdir(dd_path)
        self.configs = config

    def data_init(self):
        self.config()
        self.init_state = self.p.factory.blank_state()
        # self.init_state.options.add(option.LAZY_SOLVES)
        bh = BindingHelper(self.macho)
        bh.do_normal_bind(self.macho.rebase_blob)
        bh.do_normal_bind(self.macho.binding_blob)
        bh.do_lazy_bind(self.macho.lazy_binding_blob)
        self.pd.build_classdata(self.init_state)
        Function.build_meth_list(self.pd)
        hook_stubs(self.init_state)

    def analyze_function(self, start_addr=None, name=None):
        if name:
            start_addr = Function.retrieve_f(name=name, ret=0b100)[0]
        if start_addr in self.meth_blacklist:
            return
        st = self.init_state.copy()
        st.regs.ip = start_addr
        # st.options.add(option.LAZY_SOLVES)
        self.current_f = Function(start_addr, st, self)
        try:
            self.next_func_addr = self.macho.lc_function_starts[self.macho.lc_function_starts.index(start_addr) + 1]
        except IndexError:
            self.next_func_addr = None

        st.inspect.b('exit', when=angr.BP_BEFORE, action=branch)
        st.inspect.b('address_concretization', when=angr.BP_AFTER, action=mem_resolve)

        # cfg = self.p.analyses.CFGAccurate(keep_state=True, starts=[start_addr,], initial_state=st, call_depth=2, context_sensitivity_level=3)
        # plot_cfg(cfg, "ais4_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)
        # cdg = self.p.analyses.CDG(cfg)
        # ddg = self.p.analyses.DDG(cfg)

        # i = self.p.analyses.Identifier()

        self.simgr = sm = self.p.factory.simgr(st)
        while sm.active:
            sm.step()
        if self.store:
            self.current_f.dump()

    def analyze_class_dds(self, classref=None, classname=None):
        class_obj = class_o.retrieve(classref=classref, classname=classname)
        if class_obj.imported:
            return
        if class_obj.name in self.checked:
            return
        fp = "{}{}/{}.txt".format(self.configs.get('PATH', 'dds'), self.macho.provides, class_obj.name)
        with open(fp, 'w') as f:
            for meth in class_obj.instance_meths:
                if meth in self.class_blacklist:
                    continue
                self.analyze_function(start_addr=meth)
                f.write("---------{}----------\n".format(self.current_f.name))
                f.write("\n".join(self.current_f.dds))
                f.write("\n")
                # del self.current_f
            for meth in class_obj.class_meths:
                if meth in self.class_blacklist:
                    continue
                self.analyze_function(start_addr=meth)
                f.write("---------{}----------\n".format(self.current_f.name))
                f.write("\n".join(self.current_f.dds))
                f.write("\n")
                # del self.current_f

    def analyze_refs(self, classref=None, classname=None):
        class_obj = class_o.retrieve(classref=classref, classname=classname)
        if class_obj.imported:
            print "{} CAN NOT BE ANALYZED WITHOUT BINDING"
            return
        for meth in class_obj.instance_meths:
            if meth in self.class_blacklist:
                continue
            self.analyze_function(start_addr=meth)
            del self.current_f
        for meth in class_obj.class_meths:
            if meth in self.class_blacklist:
                continue
            self.analyze_function(start_addr=meth)
            del self.current_f

    def analyze_bin(self):

        for ref in class_o.classes_indexed_by_ref.keys():
            if ref in self.class_blacklist:
                continue
            self.analyze_class_dds(classref=ref)

print time.strftime("-START-%Y-%m-%d %H:%M:%S", time.localtime())





