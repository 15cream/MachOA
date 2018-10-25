import idc
import idautils
import idaapi
import re
from object import Object
from Utils import *


class Rule:

    rules = []

    def __init__(self, receiver=None, sel=None, data=None):
        self.receiver_str = receiver
        self.selector_str = sel
        self.receiver_ea = None
        self.selector_ea = None
        self.bin_data = data

    def analyze(self):
        ctx_rec_occurs = self.find_rec_ctx()
        ctx_sel_occurs = self.find_sel_ctx()
        s1 = set(ctx_sel_occurs)
        s2 = ctx_rec_occurs
        print 's1 - s2', len(s1 - s2)
        for f in s1-s2:
            print idc.GetFunctionName(f)
        print 's2 - s1', len(s2 - s1)
        for f in s2 - s1:
            print idc.GetFunctionName(f)
        print 'COOC:', len(s1&s2)
        print s1&s2

        if ctx_rec_occurs and ctx_sel_occurs:
            suspected_contexts = ctx_rec_occurs & set(ctx_sel_occurs)
            if len(suspected_contexts) == 1:
                print "FOUND ONE SUSPECTED CONTEXT:{}, MORE DELICATE ANALYSIS NEEDED."\
                    .format(idc.GetFunctionName(suspected_contexts[0]))
            else:
                print "FOUND MORE THAN ONE SUSPECTED CONTEXTS, THE PROPER ENTRIES WE SUGGEST ARE:"
                for entry in self.find_proper_entry(suspected_contexts):
                    print "----{}".format(idc.GetFunctionName(entry))
        else:
            print "SORRY, FAIL TO FOUND VALID INVOCATION CONTEXT."

    def find_sel_ctx(self):
        if self.selector_str and not self.selector_ea:
            if self.selector_str in self.bin_data['selrefs']:
                self.selector_ea = self.bin_data['selrefs'][self.selector_str]
            else:
                print 'CANNOT FIND SELECTOR: ', self.selector_str
                return False
        p = []
        for xref in idautils.XrefsTo(self.selector_ea):
            if idc.SegName(xref.frm) == '__text':
                fi = idaapi.get_func(xref.frm).startEA
                if fi not in p:
                    p.append(fi)
            else:
                print 'XREF OF {} NOT IN TEXT SEGMENT: {}'.format(self.selector_str, hex(xref.frm))
        return p

    def find_rec_ctx(self):
        if self.receiver_str and not self.receiver_ea:
            if self.receiver_str in self.bin_data['classrefs']:
                self.receiver_ea = self.bin_data['classrefs'][self.receiver_str]
            else:
                print 'CANNOT FIND CLASS: ', self.receiver_str
                return False
        receiver = Object(self.receiver_str, self.bin_data)
        return receiver.find_occurance()

    def find_proper_entry(self, ctx):
        return ctx

    def set_bin_data(self, d):
        self.bin_data = d

    # print 'The caller of [{} {}] could be:'.format(self.receiver_str, self.selector_str)
    # for f in self.find():
    #     func = idc.GetFunctionName(f)
    #     print func
    #     m = re.search('(?P<type>[-+]?)\[(?P<receiver>\S+?) (?P<selector>[\w:]+)\]', func)
    #     if m:
    #         type = m.group('type')
    #         receiver = m.group('receiver')
    #         selector = m.group('selector')
    #         caller = Rule(receiver=receiver, sel=selector, data=self.bin_data)
    #         caller.analyze()



