__author__ = 'gjy'

import idaapi
import idautils
import re


class Segs():

    def __init__(self):
        self.segs = dict()
        self.parsers = dict()
        self.parsers["UNDEF_parse"] = self.UNDEF_parse
        self.parsers["__got_parse"] = self.__got_parse
        self.parsers["__stubs_parse"] = self.__stubs_parse
        self.parsers["__cfstring_parse"] = self.__cfstring_parse
        self.parsers["__common_parse"] = self.__common_parse
        self.parsers["__bss_parse"] = self.__bss_parse
        self.parsers["__objc_classname_parse"] = self.__objc_classname_parse
        self.parsers["__objc_methname_parse"] = self.__objc_methname_parse
        self.parsers["__objc_methtype_parse"] = self.__objc_methtype_parse

    def UNDEF_parse(self, Start, End):
        pass

    def __got_parse(self, Start, End):
        got = dict()
        for ea in range(Start, End, 8):
            got[ea] = idc.GetDisasm(ea).split(" ")[-1]
        self.segs['got'] = got

    def __stubs_parse(self, Start, End):
        self.segs['stubs_range'] = (Start, End)

    def __common_parse(self, Start, End):
        self.segs['common_range'] = (Start, End)

    def __bss_parse(self, Start, End):
        self.segs['bss_range'] = (Start, End)

    def __cfstring_parse(self, Start, End):
        cfstring = dict()
        for ea in range(Start, End, 0x20):
            data = idc.Qword(ea + 0x10)
            length = idc.Qword(ea + 0x18)
            string = idaapi.get_many_bytes(data, length)
            cfstring[ea] = string
        self.segs['cfstring'] = cfstring

    def __objc_classname_parse(self, Start, End):
        classname = dict()
        ea = Start
        while ea < End:
            length = idc.ItemSize(ea)
            classname[ea] = idaapi.get_many_bytes(ea, length)
            ea = idc.NextNotTail(ea)
        self.segs['classname'] = classname

    def __objc_methname_parse(self, Start, End):
        methname = dict()
        ea = Start
        while ea < End:
            length = idc.ItemSize(ea)
            methname[ea] = idaapi.get_many_bytes(ea, length)
            ea = idc.NextNotTail(ea)
        self.segs['methname'] = methname

    def __objc_selrefs_parse(self, Start, End):
        selrefs = dict()
        ea = Start
        while ea < End:
            selrefs[ea] = idc.Qword(ea)
            ea = idc.NextNotTail(ea)
        self.segs['selref'] = selrefs

    def __objc_methtype_parse(self, Start, End):
        methtype = dict()
        ea = Start
        while ea < End:
            length = idc.ItemSize(ea)
            methtype[ea] = idaapi.get_many_bytes(ea, length)
            print methtype[ea]
            ea = idc.NextNotTail(ea)
        self.segs['methtype'] = methtype

    def parse(self):
        for seg in idautils.Segments():
            segname = idc.SegName(seg)
            Start = idc.SegStart(seg)
            End = idc.SegEnd(seg)
            parser = segname + "_parse"
            if parser in self.parsers:
                print segname, hex(Start), hex(End)
                self.parsers[parser](Start, End)


# segs = Segs()
# segs.parse()