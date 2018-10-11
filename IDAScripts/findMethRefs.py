import re
import pickle
import idautils
import idaapi
import idc

SecRules = {
    'NSURL': [],
    'CFStream': [],
    'NSStream': [],
}

SENSITIVES = {
    'RECEIVER': {
        # 'NSURL': [],
        # 'CFStream': [],
        # 'NSStream': [],
        # 'NSURLSession': [],
        'UIDevice': []
    },
    'SELECTOR':{
        'loadRequest:': [],
        'loadHTMLString': [],
        'initWithURLString:httpMethod:': [],
        'requestWithString:httpMethod:': [],
    },
    'VARIABLE':{

    }
}

def parse_class(ea):
    classname = idc.GetDisasm(ea).split('$_')[-1]
    if classname in SENSITIVES['RECEIVER']:
        for xref in idautils.XrefsTo(ea):
            fi = idaapi.get_func(xref.frm).startEA
            if fi not in SENSITIVES['RECEIVER'][classname]:
                SENSITIVES['RECEIVER'][classname].append(fi)

def parse_selector(ea):
    try:
        sel = idc.GetDisasm(ea).split('"')[-2]
    except IndexError as e:
        print hex(ea), idc.GetDisasm(ea), e
        sel = None
    if sel in SENSITIVES['SELECTOR']:
        for xref in idautils.XrefsTo(ea):
            fi = idaapi.get_func(xref.frm).startEA
            if fi not in SENSITIVES['SELECTOR'][sel]:
                SENSITIVES['SELECTOR'][sel].append(fi)

def parse_ivar(ea):
    pass

parser = {
    '__objc_classrefs': parse_class,
    '__objc_superrefs': parse_class,
    '__objc_selrefs': parse_selector,
    '__objc_ivar': parse_ivar
}

for seg in idautils.Segments():
    segName = idc.SegName(seg)
    if segName in ['__objc_classrefs', '__objc_superrefs', '__objc_selrefs']:  # step: 8
        for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 8):
            parser[segName](ea)
    elif segName in ['__objc_ivar']:  # step: 4
        for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 4):
            parser[segName](ea)

for type in SENSITIVES:
    if True:
        for m, meths in SENSITIVES[type].items():
            print m
            for meth in meths:
                print hex(meth), idc.GetFunctionName(meth)
#
# output = open('/home/gjy/Desktop/idapython/crefs.pkl', 'wb')
# pickle.dump([refs_of_classes, imports, classlist], output)
# output.close()