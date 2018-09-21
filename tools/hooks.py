__author__ = 'gjy'
from angr import SimProcedure
from Data.binary import MachO
import claripy
from Data.CONSTANTS import *

objc_symbols = ['_objc_retainAutoreleasedReturnValue',
                '_objc_retainAutoreleaseReturnValue',
                '_objc_autoreleaseReturnValue',
                '_objc_retain',
                '_objc_release',
                '_objc_retainAutorelease',
                ]

class stubHelper(SimProcedure):


    def run(self):
        state = self.state
        symbol = MachO.pd.stubs[state.history.parent.addr]
        if symbol.name in objc_symbols:
            return state.registers.load('x0')
        else:
            if symbol.name == '_objc_msgSend':
                imp = MachO.resolve_invoke(state, type=MSGSEND)
            else:
                imp = MachO.resolve_invoke(state, type=LAZY_BIND_F)

            if type(imp) == int or type(imp) == long:
                # self.call(imp, args=[], continue_at='ret_from_msgSend', cc=None)
                # self.jump(imp)
                return claripy.BVS("RetFrom_" + hex(imp), 64, uninitialized=True)
            elif type(imp) == str:
                return claripy.BVS(imp, 64, uninitialized=True)

    def ret_from_msgSend(self):
        print 'I just jumped to a meth_imp and returned'

