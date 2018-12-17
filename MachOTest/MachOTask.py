__author__ = 'gjy'

import sys
import time
import ConfigParser
sys.path.append('/home/gjy/Desktop/MachOA')

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

from event_simulator.CoreLocationDriver import CLDriver
from event_simulator.UIEvent import UIEvent

from SecCheck.sensitiveData import SensitiveData
from tools.Files import *


class MachOTask:

    currentTask = None

    def __init__(self, binary, store=None, visualize=None):
        self.p = angr.Project(binary)
        self.loader = self.p.loader
        self.macho = self.loader.main_object

        self.current_f = None
        self.next_func_addr = None
        self.init_state = None  # memory initialized
        self.simgr = None
        self.store = store
        self.visualize = visualize
        self.configs = None
        self.pd = MachO(self.macho, self)
        self.pre_process()
        self.checked = checked("{}{}".format(self.configs.get('PATH', 'results'), self.macho.provides))
        # self.checked = []
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
        xref_pkl = "{}{}_xrefs.pkl".format(config.get('PATH', 'dbs'), self.macho.provides)
        SensitiveData.init(xref_pkl)
        IVar.init(xref_pkl)

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

    # TO-DO
    def analyze_slice(self, start_ea=None, end_ea=None):
        self.cg = GraphView()
        st = self.init_state.copy()
        st.inspect.b('exit', when=angr.BP_BEFORE, action=branch_check)
        st.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read)
        st.inspect.b('address_concretization', when=angr.BP_AFTER, action=mem_resolve)

        s = Slice(self, st, start=start_ea, end=end_ea)
        if s:
            s.run()
            self.cg.view()

    def analyze_function(self, init_args=None, start_addr=None, sd=None, name=None):

        if name:
            start_addr = retrieve_f(name=name)['imp']
        if start_addr in self.meth_blacklist or hex(start_addr).strip('L') in self.checked:
            print 'SKIPPED: ', hex(start_addr)
            return

        self.cg = GraphView()
        st = self.init_state.copy()
        st.inspect.b('exit', when=angr.BP_BEFORE, action=branch_check)
        st.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read)
        st.inspect.b('address_concretization', when=angr.BP_AFTER, action=mem_resolve)

        f = Func(start_addr, self.macho, self, st, args=init_args, sensiData=sd).init()
        if f:
            f.analyze()
            self.cg.view()

    def analyze_bin(self):
        for ref in OCClass.classes_indexed_by_ref.keys():
            if ref in self.class_blacklist:
                continue
            self.analyze_class(classref=ref)

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

    #  deprecated
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


if __name__ == "__main__":
    print time.strftime("-START-%Y-%m-%d %H:%M:%S", time.localtime())
    analyzer = MachOTask('../samples/CsdnPlus_arm64', store=True, visualize=False)
    # CLDriver(analyzer).simulate()
    # UIEvent(analyzer).simulate()
    # analyzer.analyze_function(start_addr=0x1000999C8)
    # analyzer.analyze_function(start_addr=0x10026df08L)
    # sd = SensitiveData(receiver='UIDevice', selector='identifierForVendor')
    sd = SensitiveData(receiver='UIPasteboard', selector='generalPasteboard')

    # sd = SensitiveData(receiver='WXOMTAEnv', selector='ifv')
    for f, ea_pair in sd.as_ret.items():
        analyzer.analyze_function(start_addr=f, sd=sd)
    # sd.as_ivar()
    analyzer.clear()
    print time.strftime("-END-%Y-%m-%d %H:%M:%S", time.localtime())





