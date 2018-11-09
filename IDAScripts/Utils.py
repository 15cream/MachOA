import idc
import idautils
import idaapi
import re


def find_type_of_meth(imp):
    for xref in idautils.XrefsTo(imp):
        if idc.SegName(xref.frm) == '__objc_const':
            if idc.Qword(xref.frm + 16) == imp:
                type = idc.GetDisasm(idc.Qword(xref.frm + 8))
                m = re.search('DCB (?P<type>.+),0', type)
                if m:
                    return m.group('type')


def find_return_type(imp):
    type = find_type_of_meth(imp)
    if type:
        m = re.search('"(?P<ret>[@\w]).*', type)
        if m:
            return m.group('ret')
    else:
        print 'UNRESOLVED RET TYPE: ', type


def print_fs(fs):
    for fi in fs:
        print idc.GetFunctionName(fi)


class Others:

    def __init__(self):
        pass

    def iter_funcs(self):
        funcs = Functions()
        for f in funcs:
            name = Name(f)
            end = GetFunctionAttr(f, FUNCATTR_END)
            locals = GetFunctionAttr(f, FUNCATTR_FRSIZE)
            frame = GetFrame(f)
            if frame is None:
                continue

    def iter_struct(self):
        for struct in idautils.Structs():
            index = struct[0]
            sid = struct[1]
            name = struct[2]
            size = idc.GetStrucSize(sid)