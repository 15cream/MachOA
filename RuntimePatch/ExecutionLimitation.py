# coding=utf-8
from RuntimePatch.Utils import resolve_context
from Data.data import Data
from Data.MachO import MachO


class CLimitation:

    currentLimitation = None

    def __init__(self, ctx, type, criterion=None):
        self.ctx = ctx  # 目前限制适用于的方法体，这是一个小限制，只针对一个方法体内部
        self.valid_blocks = set()
        self.target_blocks = set()
        self.criterion_type = type
        self.criterion = criterion
        self.check_state_sensitivity = False

    def state_filter(self, state):
        """
        该方法用于simgr，【预计每种limitation有它自己的state_filter】
        :param state:
        :return: 如果该state没有必要再执行，返回True。
        """
        # 以下情况表明当前state极有可能在stub，不用过滤，等它跳转回来
        if state.addr > MachO.pd.macho.get_segment_by_name('__TEXT').get_section_by_name('__text').max_addr:
            return False

        ctx = resolve_context(state.addr)
        if ctx == self.ctx:
            if state.addr in self.target_blocks:
                if self.criterion_type == 'SEL':  # selector出现，接下来需要检查状态敏感性
                    self.check_state_sensitivity = True
                elif self.criterion_type == 'EXTERNAL_C':  # 当前block结束就不必执行了
                    pass
                elif self.criterion_type == 'BLOCK':  # 仍然需要继续追踪
                    self.check_state_sensitivity = True
                return False
            if state.addr == ctx or state.addr in self.valid_blocks:
                return False
            if self.check_state_sensitivity:  # 目前state已经不在有效block里了，主要检查有没有残留的criterion数据
                if self.is_criterion_in_state(state):
                    return False
                else:
                    return True
            else:  # 不在有效block里，又无需检查状态的敏感性，可以不再执行了
                return True
        else:
            return False  # 不是当前limitation适用的上下文，无权管理

    def is_criterion_in_state(self, state):
        ea = state.regs.bp
        while state.solver.eval(ea > state.regs.sp):
            if self.criterion in Data(state, bv=ea).expr:
                return True
            ea -= 8
        for i in range(0, 30):
            reg_data = Data(state, bv=state.regs.get('x{}'.format(i)))
            # 如果是selelctor，就直接用==，其他的呢？用in？
            if self.criterion == reg_data.expr:
                return True
        return False
