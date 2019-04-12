# coding=utf-8
import re
import claripy

from Data.CONSTANTS import FORMAT_INSTANCE
from Data.OCivar import IVar


def handle_objc_loadWeakRetained(state):
    """
    通过load获得property，注意LDRSW指令的处理
    :param state:
    :return:
    """
    instance = state.regs.x0.args[0]
    try:
        if type(state.regs.x0.args[1].args) in [list, tuple] and len(state.regs.x0.args[1].args) == 33:
            ivar_offset = state.regs.x0.args[1].args[-1]
            m = re.search('<BV32 \(<ea:0x(?P<ptr>[0-9a-f]+)L>\)IVAR_OFFSET.+>', str(ivar_offset))
            if m:
                ptr = int(m.group('ptr'), 16)
                ivar = IVar.ivars[ptr]
                expr = FORMAT_INSTANCE.format(data_type=ivar.type, ptr=hex(ptr), instance_type='IVAR',
                                              name='{}.{}'.format(ivar._class, ivar.name))
                state.regs.x0 = claripy.BVS(expr, 64)
    except AttributeError as e:
        print 'Handle _objc_loadWeakRetained: ' + str(e)