from RuntimePatch.Utils import *
from Data.OCivar import IVar
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
                    m = re.search('<BV64 SignExt\(32, 0x(?P<ptr>[0-9a-f]+)L@ivar.+\)>', str(ivar))
                    if m:
                        ptr = int(m.group('ptr'), 16)
                        ivar = IVar.ivars[ptr]
                        state.memory.store(result[0],
                                           claripy.BVS("({}){}.{}".format(ivar.type, ivar._class, ivar.name), 64).reversed)

    except SimMemoryAddressError:
        print '!!!!!!!!!!!!!!SimMemoryAddressError'


