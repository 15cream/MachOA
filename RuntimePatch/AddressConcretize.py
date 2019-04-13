# coding=utf-8
from RuntimePatch.Utils import *
from RuntimePatch.View import GraphView
from Data.OCivar import IVar, AccessedRecord
from Data.CONSTANTS import *
from Data.data import Receiver, Data
from angr.errors import SimMemoryAddressError
import re


def mem_resolve(state):
    """
    ADD     X28, X19, X8 ; X19为instance地址, x8为ivar相对instance内存的偏移，因此X28为instance内存空间中存放ivar对象的地址
    LDR     X8, [X28] ; 如果ivar为原子类型，那么x8即ivar的值；如果ivar为对象，那么x8为ivar对象的引用
    :param state:
    :return:
    """
    try:
        # 由于X19为BVS, X8为BVV, angr将二者之和具体化为一个虚拟的内存地址
        # 我们只需要记录这个对应关系，随后在内存读写事件中进一步处理
        expr = state.inspect.address_concretization_expr
        result = state.inspect.address_concretization_result
        if result and len(result) == 1:
            if expr.op == '__add__':
                instance = expr.args[0]
                ivar = expr.args[1]
                if ivar.op == 'SignExt':
                    m = re.search('<BV64 SignExt\(32, \(<ea:0x(?P<ptr>[0-9a-f]+)L>\)IVAR_OFFSET.+\)>', str(ivar))
                    if m:
                        ptr = int(m.group('ptr'), 16)
                        ivar = IVar.ivars[ptr]
                        IVar.fake_memory_and_ivar[state.solver.eval(result[0])] = {
                            'ivar': ivar,
                            'instance': instance
                        }
                        # fake_ivar_addr = claripy.BVV(ptr, 64)
                        # ivar.add_pair(fake_ivar_addr, instance)
                        # state.memory.store(result[0], fake_ivar_addr.reversed)
                        # state.memory.store(result[0], ivar.ret_latest_data().reversed)
                        # expr = FORMAT_INSTANCE.format(data_type=ivar.type, ptr=hex(ptr), instance_type='IVAR',
                        #                               name='{}.{}'.format(ivar._class, ivar.name))
                        # insn = state.project.factory.block(state.addr, size=4).capstone.insns[0]
                        # op = insn.mnemonic
                        # src_value = str(insn.op_str).split(',')[0]
                        # if op == 'ldr':
                        #     # 如果是读取ivar对象，那么将该ivar最新的值放入result中，赋值操作由mem_write事件完成
                        #     state.memory.store(result[0], ivar.ret_latest_data().reversed)
                        #     record = AccessedRecord(state, state.addr, op,
                        #                             instance=Receiver(Data(state, bv=instance), None))
                        #     ivar.add_record(record)
                        #     node = GraphView.current_view.insert_invoke(record.ea,
                        #                                                 "[{} {}]".format(record.instance.data.expr,
                        #                                                                  ivar.getter),
                        #                                                 record.state,
                        #                                                 receiver=record.instance.data.expr,
                        #                                                 selector=record.type)
                        # elif op == 'str':
                        #     # 如果是str操作，只为虚拟的ivar的对象记录当前的存放操作，而不对result进行操作。
                        #     try:
                        #         src_value = state.registers.load(src_value)
                        #         record = AccessedRecord(state, state.addr, op,
                        #                                 instance=Receiver(Data(state, bv=instance), None),
                        #                                 value=Receiver(Data(state, bv=src_value)))
                        #         ivar.add_record(record)
                        #         node = GraphView.current_view.insert_invoke(record.ea,
                        #                                                     "[{} {}]".format(record.instance.data.expr,
                        #                                                                      ivar.setter),
                        #                                                     record.state,
                        #                                                     receiver=record.instance.data.expr,
                        #                                                     selector=record.type,
                        #                                                     args=record.value)
                        #     except Exception as e:
                        #         print "该指令的src无法解析。"
                        # else:
                        #     print 'LDR/STR以外其他指令对ivar进行操作，地址:{}，指令:{}.'.format(hex(state.addr), op)

    except SimMemoryAddressError:
        print '!!!!!!!!!!!!!!SimMemoryAddressError'
