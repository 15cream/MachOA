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