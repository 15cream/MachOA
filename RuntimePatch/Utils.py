import archinfo
import claripy

from Data.MachO import MachO
from Data.OCClass import OCClass


def resolve_args(state, selector=None, symbol=None):
    args = []
    if selector:
        args.append(resolve_reg(state, state.regs.get('x0')))
        argc = selector.count(':')
        for c in range(1, argc + 2):
            reg_name = 'x{}'.format(c)
            reg_val = resolve_reg(state, state.regs.get(reg_name))
            args.append(reg_val)
        if selector == 'stringWithFormat:':
            formatString = args[2]
            fs_args = formatString.count("@")
            for c in range(3, fs_args + 3):
                reg_name = 'x{}'.format(c)
                reg_val = resolve_reg(state, state.regs.get(reg_name))
                args.append(reg_val)
    elif symbol:
        args.append(resolve_reg(state, state.regs.get('x0')))
        args.append(resolve_reg(state, state.regs.get('x1')))
    return args


def resolve_reg(state, reg):
    if reg.op == 'BVV' and '0x7f' in hex(reg.args[0]):
        reg = state.memory.load(reg).reversed

    op = reg.op
    args = reg.args

    if op == 'BVV':
        repr = resolve_addr(state, args[0])
    elif op == 'BVS':
        repr = '_'.join(args[0].split('_')[0:-2])
    else:
        repr = str(reg)
    return repr


def resolve_addr(state, addr):
    datatype = None
    for segname, seg in MachO.pd.segdata.items():
        if addr in range(seg.min_addr, seg.max_addr):
            datatype = segname
            break
    if datatype == 'classref':
        return OCClass.classes_indexed_by_ref[addr].name
    elif datatype == 'classdata':
        return OCClass.binary_class_set[addr].name
    elif datatype == 'cfstring':
        return read_cfstring(state, addr)
    elif datatype in ['cstring', 'data_const', 'text_const', 'methname']:
        return state.mem[addr].string.concrete
    else:
        return str(addr)


def resolve_var(state, classname=None, offset=None):
    c = OCClass.classes_indexed_by_name[classname]
    if c.imported:
        pass
    else:
        class_data = state.memory.load(c.class_addr + 32, 8, endness=archinfo.Endness.LE)
        ivars = state.memory.load(class_data + 0x30, 8, endness=archinfo.Endness.LE)
        ivar = ivars + (offset / 8 - 1) * 0x20 + 8
        name = state.mem[state.mem[ivar + 8].long.concrete].string.concrete
        type = state.mem[state.mem[ivar + 16].long.concrete].string.concrete
    # return claripy.BVS(classname + name + type, 64).reversed
    return claripy.BVS("({}){}.{}".format(type, classname, name), 64).reversed

def read_cfstring(state, addr):
    return state.mem[addr+16].deref.string.concrete

def read_str_from_cfstring(self, state, addr):
    str = state.memory.load(addr + 0x10, 8, endness=archinfo.Endness.LE).args[0] - 0x100000000
    length = state.memory.load(addr + 0x18, 8, endness=archinfo.Endness.LE).args[0]
    str = self.macho._read(self.macho.binary_stream, str, length)
    return str