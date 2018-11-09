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
            if '@' in formatString:
                fs_args = formatString.count("@")
                for c in range(0, fs_args):
                    sp = state.regs.sp + c * 8
                    reg_val = resolve_reg(state, sp)
                    args.append(reg_val)
            print 'TO DO: stringWithFormat args to be parsed.'
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
        if seg and addr in range(seg.min_addr, seg.max_addr):
            datatype = segname
            break
    if datatype == 'class_ref':
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
    # return claripy.BVS(class_name + name + type, 64).reversed
    return claripy.BVS("({}){}.{}".format(type, classname, name), 64).reversed


def read_cfstring(state, addr):
    return state.mem[addr+16].deref.string.concrete


def read_str_from_cfstring(self, state, addr):
    str = state.memory.load(addr + 0x10, 8, endness=archinfo.Endness.LE).args[0] - 0x100000000
    length = state.memory.load(addr + 0x18, 8, endness=archinfo.Endness.LE).args[0]
    str = self.macho._read(self.macho.binary_stream, str, length)
    return str


def expr_args(args):
    expr = ''
    if args:
        for i in range(0, len(args)):
            reg_name = 'x' + str(i)
            reg_value = args[i]
            expr += '{}: {}\n'.format(reg_name, reg_value)
    return expr


def resolve_receiver(cg, state, node):
    receiver = cg.g.nodes[node]['args'][0]
    if 'RetFrom' in receiver:
        src_node = cg.find_pnode(node, receiver.split('_')[-1])
        if src_node:
            if not cg.g.nodes[src_node]['dp']:
                cg.dpr.resolve_dp(src_node)
            # receiver = self.g.nodes[src_node]['dp'].split(' ')[0].strip('[')
            receiver = cg.g.nodes[src_node]['dp']
    return receiver
