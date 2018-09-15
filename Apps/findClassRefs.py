import re
import pickle
import idautils
import idaapi
import idc

refs_of_classes = dict()
imports = []
classlist = []

def find_sub_class(ea, xrefs):
    for xref in idautils.XrefsTo(ea):
        fn = idc.GetFunctionName(xref.frm)  # but fn could be subroutines
        m = re.search('(?P<type>[-+]?)\[(?P<receiver>\S+?) (?P<selector>[\w:]+)\]', fn)
        if m:
            cn = m.group('receiver')
            if cn not in xrefs:
                xrefs.append(cn)
        # else:
        #     find_sub_class(xref.frm, xrefs)

for seg in idautils.Segments():
    segName = idc.SegName(seg)
    start = idc.SegStart(seg)
    end = idc.SegEnd(seg)

    if segName == '__objc_classrefs':
        for ea in range(start, end, 8):
            class_ref = ea
            # class_data = idc.Qword(ea)
            name = idc.GetDisasm(class_ref).split('$_')[-1]
            xrefs = []
            for xref in idautils.XrefsTo(class_ref):
                fn = idc.GetFunctionName(xref.frm) # but fn could be subroutines
                m = re.search('(?P<type>[-+]?)\[(?P<receiver>\S+?) (?P<selector>[\w:]+)\]', fn)
                if m:
                    cn = m.group('receiver')
                    if cn not in xrefs:
                        xrefs.append(cn)
                else: # subroutine
                    find_sub_class(xref.frm, xrefs)
            refs_of_classes[name] = xrefs
    elif segName == 'UNDEF':
        for ea in range(start, end, 8):
            imports.append(idc.GetDisasm(ea).split(" ")[-1])
    elif segName == '__objc_classlist':
        for ea in range(start, end, 8):
            classlist.append(idc.GetDisasm(ea).split("$_")[-1])

output = open('/home/gjy/Desktop/idapython/crefs.pkl', 'wb')
pickle.dump([refs_of_classes, imports, classlist], output)
output.close()

