__author__ = 'gjy'

# self.next_func_addr = binary.lc_function_starts[binary.lc_function_starts.index(addr) + 1]

# x0 = self.init_state.solver.BVS(f.receiver + "_instance", 64)

fs = []
for xref in XrefsTo(0x100D5CEE0):
    fi = idaapi.get_func(xref.frm)
    start = fi.startEA
    if start not in fs:
        fs.append(start)

for f in fs:
    print hex(f), idc.GetFunctionName(f)
