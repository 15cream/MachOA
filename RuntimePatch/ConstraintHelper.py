# coding=utf-8
import copy
import claripy


def repr_constraints(state):
        cs = []
        if state.solver.constraints:
            for c in state.solver.constraints:
                # cs.append(str(c).replace('<', '').replace('>', ''))
                cs.append(str(c))
        return cs
        # return copy.deepcopy(state.solver.constraints)


def find_constraint_addtion(des, src):
        cs = []
        for c in des.constraints:
            if c not in src.constraints:
                # cs.append(str(c).replace('<', '').replace('>', ''))
                cs.append(c)
                # print c
        return cs


def constraints_event_handler(state):
    """
    当新的约束被添加到state时，该断电被触发：https://github.com/angr/angr-doc/blob/master/docs/simulation.md
    :param state:
    :return:
    """
    added_constraints = state.inspect.added_constraints
    if added_constraints[0] is not claripy.true:
        print str(added_constraints[0])

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