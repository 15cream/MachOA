__author__ = 'gjy'

import os
import sys
import ConfigParser
import commands
sys.path.append('/home/gjy/Desktop/MachOA')

from cle.backends.macho.binding import BindingHelper
from BinaryPatch.LazyBind import lazy_bind_patch
from BinaryPatch.StubResolver import *

from RuntimePatch.AddressConcretize import *
from RuntimePatch.ExitProtect import *
from RuntimePatch.ConstraintHelper import *
from RuntimePatch.View import GraphView
from RuntimePatch.StubHook import StubHelper
from RuntimePatch.Utils import *
from RuntimePatch.Function import Func
from RuntimePatch.memory_event import *
from RuntimePatch.Slice import Slice

from SecCheck.sensitiveData import SensitiveData
from tools.common import block_excess, checked_existence_in_dir


# from angrutils import *


class MachOTask:

    currentTask = None

    def __init__(self, binary, store=None, visualize=None):

        MachOTask.currentTask = self
        self.binary_path = binary
        self.p = angr.Project(binary, load_options={'auto_load_libs': False})
        self.loader = self.p.loader
        self.macho = self.loader.main_object
        self.pd = MachO(self.macho, self)
        self.to_be_analyzed = set()
        self.analyzed = set()
        self.ida_xref_pkl = None

        # self.current_f = None
        self.cg = GraphView()
        self.init_state = None  # memory initialized
        self.store = store
        self.visualize = visualize
        self.configs = None
        self.db = None
        self.logger = open('../log', mode='wb')
        self.pre_process()

        self.result_dir = "{}{}".format(self.configs.get('PATH', 'results'), self.macho.provides)
        self.class_blacklist = []
        self.meth_blacklist = [0x10011a60cL, 0x10045AB08, 0x1002FD890, 0x1003B2118, 0x10026df08L, 0x100206740L,
                               0x100c209d4L, 0x100027f68L, 0X10000C05C, 0x100127480L, 0x10078dd40L, 0x100712cfcL]

    def config(self):
        config = ConfigParser.RawConfigParser()
        config.read('config/config0')
        result_path = "{}{}".format(config.get('PATH', 'results'), self.macho.provides)
        if not os.path.exists(result_path):
            os.mkdir(result_path)
        self.configs = config
        self.db = "{}{}.pkl".format(self.configs.get('PATH', 'dbs'), self.macho.provides)
        self.ida_xref_pkl = "{}{}_xrefs.pkl".format(config.get('PATH', 'dbs'), self.macho.provides)
        os.environ['IDA_XREF_PATH'] = os.path.abspath(self.ida_xref_pkl)

    def pre_process(self):
        self.config()
        # add_options={angr.options.LAZY_SOLVES}
        if not os.path.exists(self.ida_xref_pkl):
            if not os.path.exists('{}.i64'.format(self.binary_path)):
                cmd = '{} -A -B {}'.format(self.configs.get('PATH', 'ida_path'), self.binary_path)
                commands.getstatusoutput(cmd)
            cmd = '{} -S{} {}'.format(self.configs.get('PATH', 'ida_path'), self.configs.get('PATH', 'ida_script'), self.binary_path)
            commands.getstatusoutput(cmd)
        SensitiveData.init(self.ida_xref_pkl)
        IVar.init(self.ida_xref_pkl)
        Xrefs(self.ida_xref_pkl)
        Frameworks('{}FrameworkHeaders.pkl'.format(self.configs.get('PATH', 'dbs')))
        self.init_state = self.p.factory.blank_state(add_options={angr.options.LAZY_SOLVES})
        bh = BindingHelper(self.macho)
        bh.do_normal_bind(self.macho.rebase_blob)
        bh.do_normal_bind(self.macho.binding_blob)
        bh.do_lazy_bind(self.macho.lazy_binding_blob)
        # self.macho.do_binding()

        self.pd.build(self.init_state)
        StubResolver(self.init_state, self.pd).run()
        if STUB_HOOK:
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

    def analyze_function(self, init_args=None, start_addr=None, name=None):
        if name and OCClass.retrieve_func(name=name):
            start_addr = OCClass.retrieve_func(name=name).imp
        if not start_addr:
            return None
        if start_addr in self.meth_blacklist:
            # print 'SKIPPED(IN BLACKLIST): ', hex(start_addr)
            return None
        if hex(start_addr).strip('L') in checked_existence_in_dir(self.result_dir):
            # print 'SKIPPED(ALREADY CHECKED): ', hex(start_addr)
            return checked_existence_in_dir(self.result_dir)[hex(start_addr).strip('L')]
        if block_excess(self.p, start_addr):
            return None

        self.cg = GraphView()
        st = self.init_state.copy()
        st.inspect.b('exit', when=angr.BP_BEFORE, action=branch_check)
        st.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read)
        st.inspect.b('mem_write', when=angr.BP_BEFORE, action=mem_write)
        st.inspect.b('address_concretization', when=angr.BP_AFTER, action=mem_resolve)
        st.inspect.b('constraints', when=angr.BP_AFTER, action=constraints_event_handler)

        # etree = self.p.analyses.CFGAccurate(keep_state=True, starts=[start_addr, ], initial_state=st,
        #                                   call_depth=2, context_sensitivity_level=3)
        # plot_cfg(etree, "angr_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)

        f = Func(start_addr, self.macho, self, st, args=init_args).init()
        if f:
            f.analyze()
            return self.cg.view()
            # return f.get_ret_values()

    def analyze_bin(self):
        for ref in OCClass.classes_indexed_by_ref.keys():
            if ref in self.class_blacklist:
                continue
            self.analyze_class(classref=ref)

    def analyze_class(self, classref=None, classname=None):
        class_obj = OCClass.retrieve(classref=classref, classname=classname)
        if class_obj:
            if class_obj.imported:
                return
            if class_obj.name in checked_existence_in_dir(self.result_dir):
                return
            for meth in class_obj.class_meths:
                if meth in self.meth_blacklist:
                    continue
                self.analyze_function(start_addr=meth)
            for meth in class_obj.instance_meths:
                if meth in self.meth_blacklist:
                    continue
                self.analyze_function(start_addr=meth)
        else:
            print 'CANNOT FIND THIS CLASS.'

    def clear(self):
        self.loader.close()


# if __name__ == "__main__":
#     print time.strftime("-START-%Y-%m-%d %H:%M:%S", time.localtime())
#     analyzer = MachOTask('../samples/CsdnPlus_arm64', store=True, visualize=False)
#     # CLDriver(analyzer).simulate()
#     # UIEvent(analyzer).simulate()
#     # analyzer.analyze_function(start_addr=0x1002E29CC)
#     # analyzer.analyze_class(classname='SmLocation')
#     # sd = SensitiveData(receiver='UIDevice', selector='identifierForVendor')
#     # sd = SensitiveData(receiver='UIPasteboard', selector='generalPasteboard')
#     # sd = SensitiveData(receiver='TencentMessagePack', selector='packTencentReqMessage:appId:')
#     # sd = SensitiveData(receiver='WXOMTAEnv', selector='ifv')
#     # sd = SensitiveData(receiver='SmStrUtils', selector='safe:')
#     sd = SensitiveData(receiver='SmLocation', selector='getGeoLocation')
#     sd.find_data_as_ret_value()
#     analyzer.to_be_analyzed.update(set(sd.as_ret_value.keys()))
#     # analyzer.to_be_analyzed.add(0x100326b1cL)
#     for f in analyzer.to_be_analyzed:
#         analyzer.analyze_function(start_addr=f)
#     # for f, ea_pair in sd.as_ret_value.items():
#     #     analyzer.analyze_function(start_addr=f, sd=sd)
#     analyzer.clear()
#     print time.strftime("-END-%Y-%m-%d %H:%M:%S", time.localtime())
