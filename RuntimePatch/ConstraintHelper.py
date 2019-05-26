# coding=utf-8
import copy
import claripy
from Data.data import Data


class Constraint:

    def __init__(self, bv, state):
        self.bv = bv
        self.state = state
        self.solutions = {}

    def analyze(self):
        for arg in self.bv.args:
            arg_data = Data(self.state, bv=arg)
            if arg_data.concrete is False:
                try:
                    value = self.state.solver.eval(arg)
                except Exception:
                    value = 'UNSAT'
                # arg_expr = arg_data.decode_expr()
                arg_expr = arg_data.expr
                # print '{}: {}'.format(arg_data.expr, value)
                if arg_expr in self.solutions:
                    self.solutions[arg_expr].append((str(self.bv), value))
                else:
                    self.solutions[arg_expr] = [(str(self.bv), value), ]
        return self

    @staticmethod
    def construct(current, last=None):
        """
        :param current: current history object
        :param last:
        :return:
        """
        ret = []
        if current.state.solver.constraints:
            if last is not None:
                ret.extend(last.constraints)
                current_constraints_count = len(current.state.solver.constraints)
                last_constraints_count = len(last.constraints)
                if current_constraints_count != last_constraints_count:
                    for i in range(last_constraints_count, current_constraints_count):
                        ret.append(Constraint(current.state.solver.constraints[i], current.state).analyze())
            else:
                for c in current.state.solver.constraints:
                    ret.append(Constraint(c, current.state).analyze())
        return ret


def constraints_event_handler(state):
    """
    当新的约束被添加到state时，该断点被触发：https://github.com/angr/angr-doc/blob/master/docs/simulation.md
    :param state:
    :return:
    """
    added_constraints = state.inspect.added_constraints
    if added_constraints[0] is not claripy.true:
        print str(added_constraints[0])
        # state.globals['added_constraints'].append(str(added_constraints[0]).strip('<>'), )


"""
常见的约束类型：
１．　<Bool ((unknown<RET:0x1000bc87cL>)[#146 respondsToSelector:]_38_64 & 0x1) == 0x0>：传入参数是否n响应某个方法
２．　<Bool (@"<MGSwipeTableCellDelegate>"<RET:0x1000bc8e4L>)[MGSwipeButtonsView._cell delegate]_42_64 == 0x0>：实例变量是否存在
３．　<Bool (B<GEN_PARA:0x1000bc830L>)B#909_24_64[31:0] == 0x0>：对传入参数做值判断
４．　<Bool (unknown<RET:0x1000bc8acL>)[#659 performSelector:withObject:]_43_64 == 0x0>：执行方法调用的返回值判断
５．　<Bool (unknown<RET:0x1000bc930L>)[[MGSwipeButtonsView._cell delegate] respondsToSelector:]_53_64[31:0] == 0x0>：与４类似，返回值的判断，但是有嵌套
６．　<Bool (unknown<RET:0x1000bc9f4L>)[[MGSwipeButtonsView._cell delegate] swipeTableCell:tappedButtonAtIndex:direction:fromExpansion:]_95_64[31:0] == 0x0>　https://github.com/MortimerGoro/MGSwipeTableCell/blob/master/MGSwipeTableCell/MGSwipeTableCell.h
７．　<Bool ((if ((unknown<RET:0x1000bc8acL>)[#777 performSelector:withObject:]_42_64 == 0x0) then 0x0 else 0x1) | (unknown<RET:0x1000bc9f4L>)[[MGSwipeButtonsView._cell delegate] swipeTableCell:tappedButtonAtIndex:direction:fromExpansion:]_100_64[31:0]) != 0x0>　复合类型
８．　<Bool (unknown<RET:0x1000a71f8L>)[#452 isKindOfClass:]_20_64[31:0] == 0x0>：传入参数是某一种类
９．　<Bool 0x4 >= (q<GEN_PARA:0x1000bd364L>)q#90_12_64>：估计传入参数是状态码类似，当前方法是0x1000BD364，也许可以限制caller中的路径。
１０．<Bool 0x1 < (unknown<RET:0x1000de268L>)[[MBProgressHUD allHUDsForView:] countByEnumeratingWithState:objects:count:]_39_64>
１１．<Bool (B<RET:0x1000e3138L>)[YuloreAPI registerInfoApikey:signature:]_27_64[31:0] != 0x0>
１２．<Bool ((B<RET:0x1000e3164L>)[YuloreAPI existedFolder]_28_64 & 0x1) == 0x0>

"""