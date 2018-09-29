__author__ = 'gjy'
from angr import SimProcedure
from Data.binary import MachO
import claripy
from Data.CONSTANTS import *
from Data.func import Func

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
                ret = MachO.resolve_invoke(state, type=MSGSEND)
            else:
                ret = MachO.resolve_invoke(state, type=LAZY_BIND_F)

            if type(ret) == int or type(ret) == long:

                # self.call(ret, args=[], continue_at='ret_from_msgSend', cc=None)
                # self.jump(imp)
                # f = Func(ret, MachO.pd.macho, MachO.pd.task, state)
                # f.analyze()
                # return claripy.BVS("RetFrom_" + hex(ret), 64, uninitialized=True)
                return claripy.BVS(ret, 64, uninitialized=True)
            elif type(ret) == str:
                return claripy.BVS(ret, 64, uninitialized=True)

    def ret_from_msgSend(self):
        print 'I just jumped to a meth_imp and returned'

