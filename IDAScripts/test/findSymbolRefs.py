import idautils
import idaapi
import idc
import re

symrefs = dict()
class_symbols = dict()

def psymbol(ea):
    refs = []
    symbol = idc.Name(ea)
    for xref in idautils.XrefsTo(ea):
        if idc.SegName(xref.frm) == '__stubs':
            for xxref in idautils.XrefsTo(xref.frm):
                if idc.SegName(xxref.frm) == '__text':
                    f = idc.GetFunctionName(xxref.frm)
                    refs.append(f)
                    m = re.search('(?P<type>[-+]?)\[(?P<receiver>\S+?) (?P<selector>[\w:]+)\]', f)
                    if m:
                        receiver = m.group('receiver')
                        selector = m.group('selector')
                        if receiver in class_symbols:
                            if symbol in class_symbols[receiver]:
                                class_symbols[receiver][symbol] += 1
                            else:
                                class_symbols[receiver][symbol] = 1
                        else:
                            class_symbols[receiver] = {symbol: 1}
                    else:
                        # print 'RE ERROR: ', f
                        pass
    # print idc.Name(ea), refs
    symrefs[idc.Name(ea)] = refs


for seg in idautils.Segments():
    segName = idc.SegName(seg)
    if segName == '__la_symbol_ptr':
        for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 8):
            psymbol(ea)

for c in class_symbols:
    print 'Class: ', c
    for s in class_symbols[c]:
        print s, class_symbols[c][s]
