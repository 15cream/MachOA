def repr_constraints(state):
        cs = []
        if state.solver.constraints:
            for c in state.solver.constraints:
                cs.append(str(c).replace('<', '').replace('>', ''))
        return cs
        # return copy.deepcopy(state.solver.constraints)


def find_constraint_addtion(src, des):
        cs = []
        for c in des.constraints:
            if c not in src.constraints:
                cs.append(str(c).replace('<', '').replace('>', ''))
        return cs
