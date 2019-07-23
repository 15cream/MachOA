# coding=utf-8
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
from RuntimePatch.register_event import reg_read
from RuntimePatch.StubHook import StubHelper
from RuntimePatch.Utils import *
from RuntimePatch.Function import Func
from RuntimePatch.memory_event import *
from RuntimePatch.Slice import Slice

from SecCheck.sensitiveData import SensitiveData
from tools.common import block_excess, checked_existence_in_dir
from Data.CONSTANTS import IPC, CS_LIMITED
from Results.call_sites import CallSite

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
        self.bps = []
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
        # SensitiveData.init(self.ida_xref_pkl)
        IVar.init(self.ida_xref_pkl)
        Xrefs(self.ida_xref_pkl)
        Frameworks('{}FrameworkHeaders.pkl'.format(self.configs.get('PATH', 'dbs')))
        self.init_state = self.p.factory.blank_state(add_options={angr.options.LAZY_SOLVES, angr.options.CACHELESS_SOLVER})
        bh = BindingHelper(self.macho)
        # bh.do_normal_bind(self.macho.rebase_blob)
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

    def analyze_function(self, init_args=None, start_addr=None, name=None, from_cs=False):
        if name and OCClass.retrieve_func(name=name):
            start_addr = OCClass.retrieve_func(name=name).imp
        if not start_addr:
            return None
        if start_addr in self.meth_blacklist:
            return None
        if hex(start_addr).strip('L') in checked_existence_in_dir(self.result_dir):
            return checked_existence_in_dir(self.result_dir)[hex(start_addr).strip('L')]
        if block_excess(self.p, start_addr):
            return None

        self.cg = GraphView()
        st = self.init_state.copy()
        st.inspect.b('exit', when=angr.BP_BEFORE, action=branch_check)
        st.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read)
        st.inspect.b('mem_write', when=angr.BP_BEFORE, action=mem_write)
        st.inspect.b('address_concretization', when=angr.BP_AFTER, action=mem_resolve)
        # st.inspect.b('reg_read', when=angr.BP_AFTER, action=reg_read)
        # st.inspect.b('constraints', when=angr.BP_AFTER, action=constraints_event_handler)
        # st.globals['added_constraints'] = []

        # etree = self.p.analyses.CFGAccurate(keep_state=True, starts=[start_addr, ], initial_state=st,
        #                                   call_depth=2, context_sensitivity_level=3)
        # plot_cfg(etree, "angr_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)

        f = Func(start_addr, self.macho, self, st, args=init_args).init()
        if f:
            f.analyze()
            return self.cg.view(cs_limited=from_cs)
            # return f.get_ret_values()

    def get_cfg(self, start_ea):
        st = self.init_state.copy()
        self.add_bp(st, 'exit', angr.BP_BEFORE, traverse_cfg)
        st.globals['jmp_target'] = dict()
        st.regs.ip = start_ea
        cfg = self.p.analyses.CFGAccurate(starts=[start_ea, ], initial_state=st, max_iterations=1)
        jmps_indexed_by_target = st.globals['jmp_target']
        self.clear_bps(st)
        return cfg, jmps_indexed_by_target

    def calculate_valid_blocks_to_criterion(self, ea, ctx):
        """
        给定一个程序点，计算从它所在方法体起点到达该点可能经过的所有blocks.
        但是呢，延续性不一样。
        如果该凭据是一个C函数，该点的invoke_node记录完后，这条路径的符号执行就可以结束了；
        如果该凭据是一个selref，持续到该selref不再存在于状态中；【这里其实有争议，比如你用切片分析】
        如果说该凭据是一个block...
        ！但，我们这里，只计算该点之前可能经历的blocks。至于之后的事情，别人来管
        :param:
        :return:
        """
        valid_blocks = set()  # 从方法起点到达target所要经过的所有可能blocks
        target_blocks = set()

        st = self.init_state.copy()
        self.add_bp(st, 'exit', angr.BP_BEFORE, traverse_cfg)
        st.globals['jmp_target'] = dict()
        st.regs.ip = ctx
        cfg = self.p.analyses.CFGAccurate(starts=[ctx, ], initial_state=st, max_iterations=1)
        jmps_indexed_by_target = st.globals['jmp_target']
        self.clear_bps(st)

        target_block = cfg.get_any_node(ea, anyaddr=True)
        valid_blocks.add(target_block.addr)
        target_blocks.add(target_block.addr)
        if not target_block or target_block.addr not in jmps_indexed_by_target:
            if target_block.addr == ctx:  # 即target出现在第一个代码块
                pass
            else:
                print 'ERROR.'
                return None

        srcs = set(jmps_indexed_by_target[target_block.addr])
        while srcs:
            new_srcs = set()
            for src in srcs:
                src_block = cfg.get_any_node(src, anyaddr=True)
                if src_block and src_block.addr in jmps_indexed_by_target:
                    if src_block.addr not in valid_blocks:
                        new_srcs.update(set(jmps_indexed_by_target[src_block.addr]))
                    valid_blocks.add(src_block.addr)
            srcs = new_srcs

        return valid_blocks, target_blocks

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

    def add_bp(self, state, event, when, handler):
        self.bps.append((event, state.inspect.b(event, when=when, action=handler)))

    def clear_bps(self, state):
        for (event, bp) in self.bps:
            state.inspect.remove_breakpoint(event, bp=bp)
        self.bps = []

    # deprecated
    def analyze_with_cs(self, call_string):
        # 给出一个callStack，根据栈进行符号执行
        print '----- Here is a callString ------.'
        call_string.stack.reverse()
        execution_limits = dict()
        index = 0
        for method in call_string.stack:
            index += 1
            if index == len(call_string.stack):
                execution_limits['destination'] = method  # 目标程序点，如果发现一个方法调用为des就可以终止执行了
                break

            callee = call_string.stack[index]
            execution_limits[method.ea] = {
                'target': callee.ea,  # 当前方法体内(caller_ctx)执行到方法调用target时，进入该target
                'paths': set(),
                'sensitive_blocks': set(),
            }
            print 'in method {}, {} may be invoked.'.format(method.description, callee.description)

            st = self.init_state.copy()
            self.add_bp(st, 'exit', angr.BP_BEFORE, traverse_cfg)
            st.globals['jmp_target'] = dict()
            st.regs.ip = method.ea
            cfg = self.p.analyses.CFGAccurate(starts=[method.ea, ], initial_state=st)
            jmps_indexed_by_target = st.globals['jmp_target']
            self.clear_bps(st)

            # 有两种限制类型，一是根据selector，二是subroutine的被调用地址；且不会同时出现。
            limits = call_string.extra[(method.ea, callee.ea)]
            blocks = set()  # 从方法起点到达该block所要经过的所有可能block
            src_list = set()
            if 'sel' in limits:
                for sel_occur in limits['sel']:
                    block_where_sel_occurs = cfg.get_any_node(sel_occur, anyaddr=True)
                    blocks.add(block_where_sel_occurs.addr)
                    if not block_where_sel_occurs or block_where_sel_occurs.addr not in jmps_indexed_by_target:  # 怎么会呢？
                        if block_where_sel_occurs.addr == method.ea:  # 就是第一个代码块
                            print 'selector appears in the first block at {}.'.format(hex(block_where_sel_occurs.addr))
                        else:
                            print 'ERROR.'
                        continue
                    print 'selector appears in the block started at {}.'.format(hex(block_where_sel_occurs.addr))
                    src_list.update(set(jmps_indexed_by_target[block_where_sel_occurs.addr]))
            else:
                for xref_of_sub in limits:
                    block_where_sub_refs = cfg.get_any_node(xref_of_sub, anyaddr=True)
                    blocks.add(block_where_sub_refs.addr)
                    if not block_where_sub_refs or block_where_sub_refs.addr not in jmps_indexed_by_target:
                        if block_where_sub_refs.addr == method.ea:  # 就是第一个代码块
                            print 'subroutine is referred in the first block at {}.'.format(hex(block_where_sub_refs.addr))
                        else:
                            print 'ERROR.'
                        continue
                    print 'subroutine is referred in the block started at {}.'.format(hex(block_where_sub_refs.addr))
                    src_list.update(set(jmps_indexed_by_target[block_where_sub_refs.addr]))

            execution_limits[method.ea]['sensitive_blocks'].update(blocks)
            blocks = set()

            while src_list:
                new_src_list = set()
                for src in src_list:
                    src_block = cfg.get_any_node(src, anyaddr=True)
                    if src_block and src_block.addr in jmps_indexed_by_target:
                        new_src_list.update(set(jmps_indexed_by_target[src_block.addr]))
                        blocks.add(src_block.addr)
                src_list = new_src_list

            execution_limits[method.ea]['paths'].update(blocks)
            block_str = ''
            for b in blocks:
                block_str += hex(b) + ', '
            print 'We may go through blocks {} to reach the invocation.'.format(block_str)
            print ''

        print 'Start Symbolic Execution.'
        self.cg = GraphView()
        st = self.init_state.copy()
        self.add_bp(st, 'exit', angr.BP_BEFORE, branch_check)
        self.add_bp(st, 'mem_read', angr.BP_AFTER, mem_read)
        self.add_bp(st, 'mem_write', angr.BP_BEFORE, mem_write)
        self.add_bp(st, 'address_concretization', angr.BP_AFTER, mem_resolve)
        # self.add_bp(st, 'constraints', angr.BP_AFTER, constraints_event_handler)
        st.globals['added_constraints'] = []

        f = Func(call_string.stack[0].ea, self.macho, self, st, args=None, limits=execution_limits).init()
        if f:
            f.analyze()
            self.cg.view()
        self.clear_bps(st)

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
