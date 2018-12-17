import re
import claripy
import archinfo
from types import *
from Data.MachO import MachO
from Data.OCClass import OCClass
from Data.OCFunction import OCFunction
from tools.oc_type_parser import *


class Data(object):

    def __init__(self, state, ea=None, reg=None):
        self.state = state
        self.ea = ea
        self.reg = reg

        self.type = None
        self.expr = None
        self.concrete = False
        self.is_instance = False

        if type(self.reg) is not NoneType:
            self.resolve_reg()

    def resolve_reg(self):
        """
        Register could be BVV or BVS.
        :return:
        """
        reg = self.reg
        state = self.state
        if reg.op == 'BVV' and '0x7f' in hex(reg.args[0]):
            reg = state.memory.load(reg).reversed

        op = reg.op
        args = reg.args

        if op == 'BVV':
            self.concrete = True
            expr = self.resolve_addr(state, args[0])
        elif op == 'BVS':
            expr = '_'.join(args[0].split('_')[0:-2])
        else:  # expression
            expr = str(reg)
        self.expr = expr

    def resolve_addr(self, state, addr):
        """
        According the address, find the segment and data_type ,dref the string expr.
        :param state:
        :param addr:
        :return:
        """
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

    @staticmethod
    def read_cfstring(state, addr):
        return state.mem[addr + 16].deref.string.concrete


class SEL:

    def __init__(self, data):
        self.data = data
        self.state = data.state
        self.expr = data.expr
        self.args = self.resolve_args()

    def resolve_args(self):
        args = []
        for c in range(0, self.expr.count(':')):
            reg_name = 'x{}'.format(c + 2)
            reg = Data(self.state, reg=self.state.regs.get(reg_name))
            args.append(reg)
        if self.expr == 'stringWithFormat:':
            format_string = args[0].expr
            fs_args = format_string.count("@")
            for c in range(0, fs_args):
                sp = self.state.regs.sp + c * 8
                reg = Data(self.state, sp)
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

        if self.data.concrete:
            if self.data.is_instance:
                self.type = '-'  # BVV, string
            else:
                if self.expr in OCClass.classes_indexed_by_name:
                    self.oc_class = OCClass.classes_indexed_by_name[self.expr]
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

            # Now, you know the selector, infer the unknown receiver type.
            if data_type == 'unknown':
                if self.selector.expr in OCFunction.meth_indexed_by_sel:
                    ret = []
                    for rec in OCFunction.meth_indexed_by_sel[self.selector.expr]:
                        # print rec
                        pass

            if type_to_str(data_type) in OCClass.classes_indexed_by_name:
                self.oc_class = OCClass.classes_indexed_by_name[type_to_str(data_type)]
        else:
            self.expr = expr


# if 'instance' in expr:
#     self.expr = expr.split('_')[0]
#     self.type = '-'
# elif '@' in expr:
#     self.expr = expr.split('@')[-1].strip('"')
#     self.type = '-'

# occlass = OCFunction.meth_data[meth_imp]['class']
# if type == '+':
#     state.regs.x0 = state.solver.BVV(occlass.classref_addr, 64)
# else:
#     state.regs.x0 = state.solver.BVS(occlass.name, 64)

