# coding=utf-8
import angr
from RuntimePatch.Utils import resolve_context
from Data.data import Data
from Data.MachO import MachO


class CLimitation:

    pools = dict()

    def __init__(self, ctx, type, target_str=None, target_ea=[]):
        """

        :param ctx: 执行约束发生的上下文
        :param type: 约束类型，MSG, C, BLOCK
        """
        self.ctx = ctx
        self.criterion_type = type
        self.target_str = target_str or ''
        self.target_ea = target_ea
        self.target_api = None

        self.check_state_sensitivity = False
        self.valid_blocks = set()
        self.target_blocks = set()
        self.id = self.ctx  # TODO 不严谨

        if self.id not in CLimitation.pools:
            CLimitation.pools[self.id] = self
        else:
            print "错误：当前方法相关CLimitation已经存在于限制条件池中"

    @staticmethod
    def clear():
        CLimitation.pool = dict()

    @staticmethod
    def filter(state):
        ctx = resolve_context(state.addr)
        if ctx in CLimitation.pools:
            return CLimitation.pools[ctx].state_filter(state)
        else:
            return False

    def state_filter(self, state):
        # 对state进行筛选，如果该state没有必要再执行则返回 True。
        # 作用于simgr, 进行 state_filter
        if state.addr > MachO.pd.segdata['code'].max_addr:
            return False

        if state.addr in self.target_blocks:
            if self.criterion_type == 'MSG':
                self.check_state_sensitivity = True
            elif self.criterion_type == 'C':  # subroutine or stub_code
                pass
            elif self.criterion_type == 'BLOCK':
                self.check_state_sensitivity = True
            return False

        if state.addr == self.ctx or state.addr in self.valid_blocks:
            return False

        if self.check_state_sensitivity:
            if self.is_criterion_in_state(state):
                return False
            else:
                return True
        else:
            return True  # don't need to check state and has run out of valid blocks

    def is_criterion_in_state(self, state):
        ea = state.regs.bp
        while state.solver.eval(ea > state.regs.sp):
            if self.target_str in Data(state, bv=ea).expr:
                return True
            ea -= 8
        for i in range(0, 30):
            reg_data = Data(state, bv=state.regs.get('x{}'.format(i)))
            if self.target_str == reg_data.expr:  # TODO '==' is not adaptive
                return True
        return False

    def calculate_valid_blocks_to_criterion(self):
        """
        给定一个程序点，计算从它所在方法体起点到达该点可能经过的所有blocks.
        但是呢，延续性不一样。
        如果该凭据是一个C函数，该点的invoke_node记录完后，这条路径的符号执行就可以结束了；
        如果该凭据是一个selref，持续到该selref不再存在于状态中；【这里其实有争议，比如你用切片分析】
        如果说该凭据是一个block...
        ！但，我们这里，只计算该点之前可能经历的blocks。至于之后的事情，别人来管
        :param:
        :return:
        """
        valid_blocks = set()  # 从ctx起点到达ea所要经过的所有可能blocks
        target_blocks = set()  # ea所在block
        ctx = self.ctx
        cfg, jmps_indexed_by_target = MachO.pd.task.get_cfg(ctx)
        srcs = set()

        for ea in self.target_ea:
            target_block = cfg.get_any_node(ea, anyaddr=True)
            valid_blocks.add(target_block.addr)
            target_blocks.add(target_block.addr)
            if not target_block or target_block.addr not in jmps_indexed_by_target:
                if target_block.addr == ctx:  # 即target出现在第一个代码块
                    pass
                else:
                    print 'ERROR.'
                    return None
            else:
                srcs.update(set(jmps_indexed_by_target[target_block.addr]))

        while srcs:
            new_srcs = set()
            for src in srcs:
                src_block = cfg.get_any_node(src, anyaddr=True)
                if src_block and src_block.addr in jmps_indexed_by_target:
                    if src_block.addr not in valid_blocks:
                        new_srcs.update(set(jmps_indexed_by_target[src_block.addr]))
                    valid_blocks.add(src_block.addr)
            srcs = new_srcs

        self.valid_blocks = valid_blocks
        self.target_blocks = target_blocks
