# coding=utf-8
from RuntimePatch.Utils import *
from RuntimePatch.View import GraphView
from Data.OCivar import IVar, AccessedRecord
from Data.CONSTANTS import *
from Data.data import Receiver, Data
from angr.errors import SimMemoryAddressError
import re
import claripy


def mem_resolve(state):
    """
    ADD     X28, X19, X8 ; X19为instance地址, x8为ivar相对instance内存的偏移，因此X28为instance内存空间中存放ivar对象的地址
    LDR     X8, [X28] ; 如果ivar为原子类型，那么x8即ivar的值；如果ivar为对象，那么x8为ivar对象的引用
    指令也可以是：LDR   X8, [X19, X8]
    由于instance对象地址为８字节，ivar_offset的值为４字节，angr默认使用ＳignExt，这意味者x19与x8相加以后x8会被扩展。
    为了便于记录和解析，我们需要把x8的表示还原回去。
    之所以address_concretization断点会断在这里，是因为需要从ivar的地址中读取ivar，而ivar的地址由两个符号相加得到。通常情况下，这会是一个随机值。
    后续则会从这个随机地址中读取值，所以我们要在这里对conretize的地址值做一个处理，再结合mem_read事件处理，获得一个符合逻辑的值。
    :param state:
    :return:
    """
    try:
        expr = state.inspect.address_concretization_expr
        result = state.inspect.address_concretization_result
        strategy = state.inspect.address_concretization_strategy
        action = state.inspect.address_concretization_action
        state.inspect.address_concretization_add_constraints = False

        # if result and len(result) == 1:
        if expr.op == '__add__':
            instance = expr.args[0]
            ivar = expr.args[1]
            if ivar.op == 'SignExt':
                m = re.search('<BV64 SignExt\(32, \(<ea:0x(?P<ptr>[0-9a-f]+)L>\)IVAR_OFFSET.+\)>', str(ivar))
                if m:
                    ptr = int(m.group('ptr'), 16)
                    ivar = IVar.ivars[ptr]
                    # 实际上ivar的地址应该在instance的内存空间里，但由于在符号执行时没有为instance object 分配内存，ivar也并不存在。
                    # 这里构造一个虚拟的地址，直接在ivar_offset的地址上加１．
                    # 需要mem_read/write事件的配合
                    # state.inspect.address_concretization_result[0] = ptr + 1
                    IVar.fake_memory_and_ivar[ptr + 1] = {
                        'ivar': ivar,
                        'instance': instance
                    }
                    state.inspect.address_concretization_result = [ptr + 1, ]
                    if state.solver.eval(state.inspect.address_concretization_expr == state.inspect.mem_read_address):
                        state.globals[str(state.inspect.address_concretization_expr)] = ptr + 1

                    if state.solver.eval(state.inspect.address_concretization_expr == state.inspect.mem_write_address):
                        state.globals[str(state.inspect.address_concretization_expr)] = ptr + 1
                        # TODO 待确认是否要做或者是否在这里实现：除此之外，还原被扩展的值，主要是方便记录和解析。

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
