# coding=utf-8
from Data.data import Receiver, Data
from RuntimePatch.View import GraphView

__author__ = 'gjy'
from Data.OCivar import IVar, AccessedRecord
from Data.MachO import MachO, BSS
from Data.CONSTANTS import *
import claripy


def mem_read(state):
    length = state.inspect.mem_read_length * 8
    if str(state.inspect.mem_read_address) in state.globals:
        ptr = state.globals[str(state.inspect.mem_read_address)]
    else:
        ptr = state.solver.eval(state.inspect.mem_read_address)
    content = state.inspect.mem_read_expr
    insn = state.project.factory.block(state.addr, size=4).capstone.insns[0]
    op = insn.mnemonic
    src_value = str(insn.op_str).split(',')[0]

    if ptr in IVar.ivars:
        ivar = IVar.ivars[ptr]
        state.inspect.mem_read_expr = claripy.BVS(FORMAT_IVAR_OFFSET.format(ptr=hex(ptr)), length, uninitialized=True)
    elif ptr in IVar.fake_memory_and_ivar:
        ivar = IVar.fake_memory_and_ivar[ptr]['ivar']
        instance = IVar.fake_memory_and_ivar[ptr]['instance']
        state.inspect.mem_read_expr = ivar.ret_latest_data(length=length)
        record = AccessedRecord(state, state.addr, op,
                                instance=Receiver(Data(state, bv=instance), None))
        ivar.add_record(record)
        # node = GraphView.current_view.insert_invoke(record.ea,
        #                                             "[{} {}]".format(record.instance.data.expr,
        #                                                              ivar.getter),
        #                                             record.state,
        #                                             receiver=record.instance.data.expr,
        #                                             selector=record.type)
        # GraphView.current_view.g.nodes[node]['ret'] = ivar.ret_latest_data()

    elif MachO.pd.segdata['common'] and ptr in range(MachO.pd.segdata['common'].min_addr,
                                                     MachO.pd.segdata['common'].max_addr):
        state.inspect.mem_read_expr = claripy.BVS(FORMAT_COMMON_DATA.format(ptr=hex(ptr)), length, uninitialized=True)

    elif ptr in range(MachO.pd.segdata['bss'].min_addr, MachO.pd.segdata['bss'].max_addr):
        state.inspect.mem_read_expr = BSS.get(ptr).load(length)

    elif ptr in range(MachO.pd.segdata['got'].min_addr, MachO.pd.segdata['got'].max_addr):
        if ptr % 2:
            state.inspect.mem_read_expr = claripy.BVS(MachO.pd.macho.get_symbol_by_address_fuzzy(ptr - GOT_ADD_ON).name,
                                                      length,
                                                      uninitialized=True)
        else:
            state.inspect.mem_read_expr = claripy.BVV(ptr + GOT_ADD_ON, length)


def mem_write(state):
    resolved_data = None
    length = state.inspect.mem_write_length * 8
    # TODO: UnsatError("CompositeSolver is already unsat")
    if str(state.inspect.mem_write_address) in state.globals:
        ptr = state.globals[str(state.inspect.mem_write_address)]
    else:
        ptr = state.solver.eval(state.inspect.mem_write_address)
    insn = state.project.factory.block(state.addr, size=4).capstone.insns[0]
    op = insn.mnemonic

    if ptr in IVar.ivars:
        ivar = IVar.ivars[ptr]
        resolved_data = FORMAT_IVAR_OFFSET.format(ptr=hex(ptr))

    elif ptr in IVar.fake_memory_and_ivar:
        ivar = IVar.fake_memory_and_ivar[ptr]['ivar']
        instance = IVar.fake_memory_and_ivar[ptr]['instance']
        record = AccessedRecord(state, state.addr, op,
                                instance=Receiver(Data(state, bv=instance), None),
                                value=Data(state, bv=state.inspect.mem_write_expr))
        ivar.add_record(record)
        # node = GraphView.current_view.insert_invoke(record.ea,
        #                                             "[{} {}]".format(record.instance.data.expr,
        #                                                              ivar.setter),
        #                                             record.state,
        #                                             receiver=record.instance.data.expr,
        #                                             selector=record.type,
        #                                             args=[record.value, ])

    elif MachO.pd.segdata['common'] and ptr in range(MachO.pd.segdata['common'].min_addr,
                                                     MachO.pd.segdata['common'].max_addr):
        resolved_data = FORMAT_COMMON_DATA.format(ptr=hex(ptr))

    elif ptr in range(MachO.pd.segdata['bss'].min_addr, MachO.pd.segdata['bss'].max_addr):
        # 并不改变写入值，只是对写入值进行记录
        BSS.get(ptr).store(state.inspect.mem_write_expr)
