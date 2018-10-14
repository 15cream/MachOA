import pickle
import idautils
import idaapi
import idc
import re

bssXrefs = dict()

def parse_bss(ea):
    print hex(ea)
    xrefs = []
    for xref in idautils.XrefsTo(ea):
        op = idc.GetMnem(xref.frm)
        if 'LDR' in op:
            next_item = xref.frm + 4
            next_op = idc.GetMnem(next_item)
            print idc.GetFunctionName(xref.frm), next_op, idc.GetDisasm(next_item)
        # print hex(xref.frm), idc.GetFunctionName(xref.frm), idc.GetDisasm(xref.frm), idc.GetMnem(xref.frm)

def parse_ivar(ea):
    xrefs = []
    name = idc.Name(ea)
    type = idc.GetDisasm(ea)
    for xref in idautils.XrefsTo(ea):
        op = idc.GetMnem(xref.frm)
        if 'LDR' in op:
            next_item = xref.frm + 4
            next_op = idc.GetMnem(next_item)
            print hex(next_item), idc.GetFunctionName(xref.frm), idc.GetDisasm(next_item)

def find_possible_caller(receiver=None, selector=None, name=None):
    if name:
        m = re.search('(?P<type>[-+]?)\[(?P<receiver>\S+?) (?P<selector>[\w:]+)\]', name)
        if m:
            type = m.group('type')
            receiver = m.group('receiver')
            selector = m.group('selector')

for seg in idautils.Segments():
    segName = idc.SegName(seg)
    if segName in ['__objc_classrefs', '__objc_superrefs', '__objc_selrefs']:  # step: 8
        for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 8):
            parser[segName](ea)


# for seg in idautils.Segments():
#     segName = idc.SegName(seg)
#     if segName == '__bss':  # step: 8
#         for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 8):
#             parse_bss(ea)
#             pass
#     elif segName == '__objc_ivar':
#         for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 4):
#             parse_bss(ea)
parse_ivar(0x0100D6C62C)

