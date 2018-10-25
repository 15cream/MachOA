import idautils
import idc
import idaapi



def find_invoke_pats(seg):
    dispatch = 0
    msgSend = 0
    for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 8):
        symbol = idc.Name(ea)
        if 'dispatch' in symbol:
            stub = list(XrefsTo(ea))[0].frm - 4
            c = len(list(XrefsTo(stub)))
            dispatch += c
            print symbol, hex(stub), c
        elif 'msgSend' in symbol:
            stub = list(XrefsTo(ea))[0].frm - 4
            c = len(list(XrefsTo(stub)))
            msgSend += c
            print symbol, hex(stub), c
    print 'dispatch: ', dispatch
    print 'msgSend: ', msgSend


def class_statistics(seg):
    # for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 8):
    count = (idc.SegEnd(seg) - idc.SegStart(seg)) / 8
    print 'Binary Classes count: ', count



def main():
    for seg in idautils.Segments():
        segName = idc.SegName(seg)
        if segName == '__la_symbol_ptr':
            find_invoke_pats(seg)
        elif segName == '__objc_classlist':
            class_statistics(seg)


for xref in XrefsTo(0x100D45608):
    fi = idaapi.get_func(xref.frm).startEA
    if fi not in xrefs:
        xrefs.append(fi)