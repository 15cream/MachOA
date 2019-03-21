from RuntimePatch.Utils import *
from Data.OCivar import IVar
from Data.CONSTANTS import *
from angr.errors import SimMemoryAddressError
import re


def mem_resolve(state):
    try:
        expr = state.inspect.address_concretization_expr
        result = state.inspect.address_concretization_result
        if result and len(result) == 1:
            if expr.op == '__add__':
                instance = expr.args[0]
                ivar = expr.args[1]
                if ivar.op == 'SignExt':
                    # m = re.search('<BV64 SignExt\(32, 0x(?P<ptr>[0-9a-f]+)L@ivar.+\)>', str(ivar))
                    m = re.search('<BV64 SignExt\(32, \(<ea:0x(?P<ptr>[0-9a-f]+)L>\)IVAR_OFFSET.+\)>', str(ivar))
                    if m:
                        ptr = int(m.group('ptr'), 16)
                        ivar = IVar.ivars[ptr]
                        # expr = FORMAT_IVAR.format(ivar_type=ivar.type, instance=ivar._class, ivar_name=ivar.name)
                        expr = FORMAT_INSTANCE.format(data_type=ivar.type, ptr=hex(ptr), instance_type='IVAR',
                                                      name='{}.{}'.format(ivar._class, ivar.name))
                        state.memory.store(result[0],
                                           claripy.BVS(expr, 64).reversed)

    except SimMemoryAddressError:
        print '!!!!!!!!!!!!!!SimMemoryAddressError'


def mem_resolve2(state):
    instance = state.regs.x0.args[0]
    if len(state.regs.x0.args[1].args) == 33:
        ivar_offset = state.regs.x0.args[1].args[-1]
    else:
        return
    m = re.search('<BV32 \(<ea:0x(?P<ptr>[0-9a-f]+)L>\)IVAR_OFFSET.+>', str(ivar_offset))
    if m:
        ptr = int(m.group('ptr'), 16)
        ivar = IVar.ivars[ptr]
        expr = FORMAT_INSTANCE.format(data_type=ivar.type, ptr=hex(ptr), instance_type='IVAR',
                                      name='{}.{}'.format(ivar._class, ivar.name))
        state.regs.x0 = claripy.BVS(expr, 64)

