__author__ = 'gjy'
import ConfigParser
import time
import sys
sys.path.append('/home/gjy/Desktop/MachOA')
import os

import angr.engines.successors
import angr.sim_state
from cle.backends.macho.binding import BindingHelper

from BinaryPatch.LazyBind import lazy_bind_patch
from BinaryPatch.StubResolver import *
from BinaryPatch.Utils import *

from RuntimePatch.AddressConcretize import *
from RuntimePatch.ExitProtect import *
from RuntimePatch.View import GraphView
from RuntimePatch.StubHook import StubHelper
from RuntimePatch.Utils import *
from RuntimePatch.Function import Func
from RuntimePatch.mem_read import *
from RuntimePatch.Slice import Slice

from Data.OCFunction import OCFunction
# from tools.Files import *


class MachOTask:

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
        self.pd = MachO(self.macho, self)
        self.pre_process()
        # self.checked = checked("{}{}".format(self.configs.get('PATH', 'results'), self.macho.provides))
        self.checked = []
        self.db = "{}{}.pkl".format(self.configs.get('PATH', 'dbs'), self.macho.provides)
        self.cg = GraphView()
        self.logger = open('../log', mode='wb')

        self.class_blacklist = []
        self.meth_blacklist = []

    def config(self):
        config = ConfigParser.RawConfigParser()
        config.read('../config/config0')
        result_path = "{}{}".format(config.get('PATH', 'results'), self.macho.provides)
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

        self.pd.build(self.init_state)
        StubResolver(self.init_state, self.pd).run()
        self.p.hook(lazy_bind_patch(self.init_state, self.macho), StubHelper)

    def analyze_slice(self, start_addr=None, end_addr=None):
        self.cg = GraphView()
        s = Slice(start_addr, self, end=end_addr)
        s.run()

    def analyze_function(self, start_addr=None, name=None):
        self.cg = GraphView()
        if name:
            start_addr = retrieve_f(name=name)['imp']
        if start_addr in self.meth_blacklist or hex(start_addr).strip('L') in self.checked:
            print 'SKIPPED: ', hex(start_addr)
            return
        st = self.init_state.copy()
        st.inspect.b('exit', when=angr.BP_BEFORE, action=branch_check)
        st.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read)
        st.inspect.b('address_concretization', when=angr.BP_AFTER, action=mem_resolve)

        f = Func(start_addr, self.macho, self, st)
        f.init_regs()
        f.analyze()
        self.cg.view()
        # except Exception as e:
        #     print hex(start_addr), 'Failed to analyze: ', e

        # cfg = self.p.analyses.CFGAccurate(keep_state=True, starts=[start_addr, ], initial_state=st, call_depth=2,
        #                               context_sensitivity_level=3)
        # plot_cfg(cfg, "ais4_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)

    def analyze_bin(self):
        for ref in OCClass.classes_indexed_by_ref.keys():
            if ref in self.class_blacklist:
                continue
            self.analyze_class(classref=ref)

    def analyze_class_dds(self, classref=None, classname=None):
        class_obj = OCClass.retrieve(classref=classref, classname=classname)
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
        class_obj = OCClass.retrieve(classref=classref, classname=classname)
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

    def clear(self):
        self.loader.close()


print time.strftime("-START-%Y-%m-%d %H:%M:%S", time.localtime())
analyzer = MachOTask('../samples/DoubanRadio_arm64', store=True, visualize=False)
analyzer.analyze_function(0x100649CD8)
# analyzer.analyze_class(classname='QQApiMessage')
# analyzer.analyze_bin()
fs = [4297314720L, 4298958052L, 4301420752L, 4301785164L, 4299675236L, 4304217968L, 4299679092L, 4298747060L, 4300090440L, 4301805964L, 4298072216L, 4296458748L, 4300284124L, 4302979732L]
# for f in [4298548040L, 4301779228L]:
#     analyzer.analyze_function(f)
# analyzer.analyze_function(0x10025D148)
# analyzer.analyze_slice(0x1005ffe24, end_addr=0x100600484)
# analyzer.analyze_slice(0x10025E128)
# analyzer.analyze_class(classname='DOULocationManager')
analyzer.clear()

# print time.strftime("-END-%Y-%m-%d %H:%M:%S", time.localtime())
#
# if __name__ == '__main__':
#     analyzer = MachOTask('/home/gjy/Desktop/MachOA/samples/WeiBo_arm64', store=True, visualize=False)
#     args = sys.argv[1:]
#     startEA = int(args[0], 10)
#     endEA = int(args.pop(), 10)
#     if startEA == endEA:
#         analyzer.analyze_function(startEA)
#     else:
#         analyzer.analyze_slice(startEA, end_addr=endEA)




