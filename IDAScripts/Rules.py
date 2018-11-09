from object import Object
import idc
import idautils
import idaapi
import commands
import os
import time


class Rule:

    def __init__(self, receiver=None, sel=None, data=None):
        self.receiver_str = receiver
        self.selector_str = sel
        self.receiver_ea = None
        self.selector_ea = None
        self.receiver_ctx = dict()
        self.selector_ctx = dict()
        self.suspected_contexts = []
        self.bin_data = data

    def isClassMethod(self):
        return False

    def analyze(self):
        print 'Try to find contexts where [{} {}] invoke happens.'.format(self.receiver_str, self.selector_str)
        self.find_sel_ctx()
        self.find_rec_ctx()
        if self.isClassMethod():
            pass  # Should do some other work.
        else:
            print 'Selector occurs in {} functions. '.format(len(self.selector_ctx.keys()))
            for ctx in self.selector_ctx:
                print "ADDR: {}, FUNCTION: {}".format(hex(ctx), idc.GetFunctionName(ctx))
            print 'Receiver occurs in {} functions. '.format(len(self.receiver_ctx.keys()))
            for ctx in self.receiver_ctx:
                print "ADDR: {}, FUNCTION: {}".format(hex(ctx), idc.GetFunctionName(ctx))
            intersection_ctx = list(set(self.selector_ctx.keys()) & set(self.receiver_ctx.keys()))
            print 'The intersection of functions({}) are:'.format(len(intersection_ctx))
            for ctx in intersection_ctx:
                print "ADDR: {}, FUNCTION: {}".format(hex(ctx), idc.GetFunctionName(ctx))
                if self.slice_analysis_needed(ctx):
                    print 'STATIC SLICING NEEDED.'
                else:
                    self.code_execution(ctx)

    def find_sel_ctx(self):
        if self.selector_str and not self.selector_ea:
            if self.selector_str in self.bin_data['selrefs']:
                self.selector_ea = self.bin_data['selrefs'][self.selector_str]
            else:
                print 'CANNOT FIND SELECTOR: ', self.selector_str
                return False

        for xref in idautils.XrefsTo(self.selector_ea):
            if idc.SegName(xref.frm) == '__text':
                fi = idaapi.get_func(xref.frm).startEA
                if fi not in self.selector_ctx:
                    self.selector_ctx[fi] = [xref.frm, ]
                else:
                    self.selector_ctx[fi].append(xref.frm)
            else:
                print 'XREF OF {} NOT IN TEXT SEGMENT: {}'.format(self.selector_str, hex(xref.frm))

    def find_rec_ctx(self):
        if self.receiver_str and not self.receiver_ea:
            if self.receiver_str in self.bin_data['classrefs']:
                self.receiver_ea = self.bin_data['classrefs'][self.receiver_str]
            else:
                print 'CANNOT FIND CLASS: ', self.receiver_str
                return False
        receiver = Object(self.receiver_str, self.bin_data)
        if receiver:
            receiver.find_occurrences()
            self.receiver_ctx = receiver.get_occurrences()

    def set_bin_data(self, d):
        self.bin_data = d

    def slice_analysis_needed(self, ea):
        f = idaapi.get_func(ea)
        flowchart = idaapi.FlowChart(f)
        blocks = list(flowchart)
        instructions = (f.endEA - f.startEA) / 4
        # print len(blocks), instructions
        # return "{} , {}".format(len(blocks), instructions)
        if len(blocks) > 20:
            return True
        else:
            return False

    def code_execution(self, ea):
        # print time.strftime("-START-%Y-%m-%d %H:%M:%S", time.localtime())
        # analyzer = MachOTask('../samples/WeiBo_arm64', store=True, visualize=False)
        # analyzer.analyze_function(ea)
        # analyzer.clear()
        # print time.strftime("-END-%Y-%m-%d %H:%M:%S", time.localtime())
        # (status, output) = commands.getstatusoutput(
        #     '/home/gjy/Desktop/MachOA/venv/bin/python /home/gjy/Desktop/MachOA/MachOTest/MachOTask.py  {}'.format(ea))
        # if status == 0:
        pass
