# coding=utf-8
import re
import claripy
import archinfo
import chardet
import unicodedata
from types import *
from Data.MachO import MachO
from Data.OCClass import OCClass
from Data.OCFunction import OCFunction
from Data.CONSTANTS import FORMAT_INSTANCE, GOT_ADD_ON, performSelectors
from tools.oc_type_parser import *


class Data(object):

    def __init__(self, state, ea=None, bv=None):
        self.state = state
        self.ea = ea
        self.bv = bv

        self.type = None
        self.expr = None
        self.concrete = False
        self.is_instance = False

        if type(self.bv) is not NoneType:
            if type(self.bv) is claripy.ast.bool.Bool or type(self.bv) is bool:
                self.expr = str(self.bv)
            else:
                self.resolve_reg()
        # if type(self.ea) is not NoneType:
        #     self.resolve_addr(self.ea)

    def resolve_reg(self):
        """
        Register could be BVV or BVS.
        :return:
        """
        reg = self.bv
        state = self.state
        if reg.op == 'BVV' and '0x7f' in hex(reg.args[0]):
            reg = state.memory.load(reg).reversed

        op = reg.op
        args = reg.args

        if op == 'BVV':
            self.concrete = True
            expr = self.resolve_addr(args[0])
        elif op == 'BVS':
            expr = '_'.join(args[0].split('_')[0:-2])
        elif op == 'Concat':
            operand1 = Data(state, bv=args[0])
            operand2 = Data(state, bv=args[1])
            expr = "Concat({}, {})".format(operand1.expr, operand2.expr)
        elif op == '__add__':
            addend1 = Data(state, bv=args[0])
            addend2 = Data(state, bv=args[1])
            expr = "Add({}, {})".format(addend1.expr, addend2.expr)
        else:  # expression
            expr = str(reg)
        self.expr = expr

    def resolve_addr(self, addr):
        """
        According the address, find the segment and data_type ,dref the string expr.
        :param addr:
        :return:
        """
        state = self.state
        data_type = None
        for seg_name, seg in MachO.pd.segdata.items():
            if seg and addr in range(seg.min_addr, seg.max_addr):
                data_type = seg_name
                break
        self.type = data_type

        if data_type in ['class_ref', 'superrefs']:
            return OCClass.classes_indexed_by_ref[addr].name
        elif data_type == 'classdata':
            return OCClass.binary_class_set[addr].name
        elif data_type == 'cfstring':
            self.is_instance = True
            return Data.read_cfstring(state, addr)
        elif data_type in ['cstring', 'data_const', 'text_const', 'methname']:
            self.is_instance = True
            return state.mem[addr].string.concrete
        else:
            return str(addr)

    def mark(self):
        expr = self.expr
        if 'Marked_' in expr:
            return
        m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', expr)
        if m:
            data_type = m.group('data_type')
            if 'Marked' not in data_type:
                pts = self.pt_analyze()
                data_type = 'Marked_' + data_type
                new_val = self.state.solver.BVS(
                    FORMAT_INSTANCE.format(
                        data_type=data_type, instance_type=m.group('instance_type'),
                        ptr=m.group('ptr'), name=m.group('name')),
                    64)
                for ea in pts['ea']:
                    self.state.memory.store(ea, new_val)
                for reg in pts['bv']:
                    self.state.registers.store(reg, new_val)

    def pt_analyze(self):
        """
        We have to do the pointer analysis. ( =. =  But I remember that angr can do this on his own.
        Sorry that I forgot.)
        :return:
        """
        pts = {'ea': [], 'bv': []}
        state = self.state
        ea = state.regs.bp
        while state.solver.eval(ea > state.regs.sp):
            if Data(state, bv=ea).expr == self.expr:
                pts['ea'].append(ea)
            ea -= 8

        for i in range(0, 32):
            if Data(state, bv=state.regs.get('x{}'.format(i))).expr == self.expr:
                pts['bv'].append('x{}'.format(i))
        return pts

    @staticmethod
    def read_cfstring(state, addr):
        data = state.mem[addr + 16].deref.string.concrete
        encoding = chardet.detect(data)['encoding']
        if encoding:
            # data = data.decode(encoding).encode('utf-8')
            data = unicodedata.normalize('NFKD', data.decode(encoding)).encode('ascii', 'ignore')
        return data

    @staticmethod
    def decode(s):
        m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', s)
        if m:
            return [m.group('data_type'), m.group('instance_type'), m.group('ptr'), m.group('name')]
        else:
            return None

    def decode_expr(self):
        return Data.decode(self.expr)


class SEL:

    def __init__(self, data):
        self.data = data
        self.state = data.state
        self.expr = data.expr
        self.args = self.resolve_args()

    def rearrange_if_necessary(self):
        if self.expr in performSelectors:
            # todo 不准确
            self.state.regs.x1 = self.state.regs.x2
            self.state.regs.x2 = self.state.regs.x3
            return SEL(Data(self.state, bv=self.state.regs.x1))
        else:
            return self

    def resolve_args(self):
        args = []
        if self.expr == 'dictionaryWithObjects:forKeys:count:':
            objects = self.state.regs.x2
            keys = self.state.regs.x3
            count = int(Data(self.state, bv=self.state.regs.x4).expr)
            object_list = []
            key_list = []
            for i in range(0, count):
                object_list.append(Data(self.state, bv=objects + i * 8))
                key_list.append(Data(self.state, bv=keys + i * 8))
            args = object_list + key_list
            return args

        for c in range(0, self.expr.count(':')):
            reg_name = 'x{}'.format(c + 2)
            reg = Data(self.state, bv=self.state.regs.get(reg_name))
            args.append(reg)
        if self.expr == 'stringWithFormat:':
            format_string = args[0].expr
            fs_args = format_string.count("%")
            for c in range(0, fs_args):
                sp = self.state.regs.sp + c * 8
                reg = Data(self.state, bv=sp)
                args.append(reg)

        return args


class Receiver:

    def __init__(self, data, sel):
        self.data = data
        self.selector = sel
        self.state = data.state

        self.type = '?'
        self.expr = data.expr
        self.oc_class = None
        self.data_type = None
        self.dpr = {}  # ea: type
        self.valid = True

        if self.data.concrete:
            if self.data.is_instance:
                self.type = '-'  # BVV, string
            else:
                self.oc_class = OCClass.retrieve_by_classname(self.expr, is_superclass=False)
                self.type = '+'  # BVV, class method invoke
        else:
            self.type_infer()  # BVS, need type infer

    def type_infer(self):
        expr = self.data.expr
        m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', expr)
        if m:
            data_type = m.group('data_type').strip('Marked_')
            instance_type = m.group('instance_type')
            ptr = m.group('ptr')
            name = m.group('name')
            self.expr = name
            self.type = '-'

            self.oc_class = OCClass.retrieve_by_classname(type_to_str(data_type), is_superclass=False)
            if self.oc_class:
                self.data_type = self.oc_class.name
            else:
                self.data_type = data_type
                self.dpr[ptr] = instance_type
        else:
            self.expr = expr
            self.valid = False
            # todo 例如，mem_0，这类是完全无法解析，原因是二进制分析中的
            # 莫非根据selector进行推断

    def type_infer_by_selector(self):
        if self.selector and self.selector.expr in OCFunction.meth_indexed_by_sel:
            for f in OCFunction.meth_indexed_by_sel[self.selector.expr]:
                if f.receiver in self.expr:
                    self.oc_class = OCClass.retrieve_by_classname(f.receiver)
                    return


class Block:

    def __init__(self, state, data):
        # TODO __NSConcreteGlobalBlock
        self.data_ea = data
        self.subroutine = None
        self.data = Data(state, bv=data)
        if self.data.type == 'got':
            if self.data.concrete:
                got_ptr = int(self.data.expr) - GOT_ADD_ON
                if MachO.pd.macho.get_symbol_by_address_fuzzy(got_ptr).name == '__NSConcreteStackBlock':
                    sub = Data(state, bv=data + 0x10)
                    if sub.type == 'code' and sub.concrete:
                        subroutine = int(sub.expr)
                        if subroutine in OCFunction.meth_data:
                            self.subroutine = subroutine
            else:
                print "EXCEPTION HERE: data.Block.__init__"

        # 最开始使用的简陋方法，查找附近有没有出现subroutine的地址
        # base = state.regs.x1
        # for i in range(1, 6):
        #     ea = state.mem[base + 8 * i].long.concrete
        #     if ea in MachO.pd.macho.lc_function_starts:
        #         return ea





