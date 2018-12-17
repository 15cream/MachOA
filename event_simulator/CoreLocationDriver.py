from Data.OCClass import OCClass
from Data.OCProtocol import Protocol
from tools.oc_type_parser import parser1

import re


class CLDriver:

    def __init__(self, analyzer):
        self.delegate_protocol = 'CLLocationManagerDelegate'
        self.delegate_classes = []
        self.delegate_protocol_methods = dict()  # key:selector values=[ret_type, para1_type, para2_type...]
        self.find_delegate_class()
        self.construct_delegate_meths()
        self.analyzer = analyzer  # MachOTask

    def find_delegate_class(self):
        for ea, occlass in OCClass.binary_class_set.items():
            if self.delegate_protocol in occlass.prots:
                self.delegate_classes.append(ea)

    def simulate(self):
        for class_ea in self.delegate_classes:
            for imeth_ea, imeth_name in OCClass.binary_class_set[class_ea].instance_meths.items():
                m = re.search('(?P<type>[-+]?)\[(?P<receiver>\S+?) (?P<selector>[\w:]+)\]', imeth_name)
                if m and m.group('selector') in self.delegate_protocol_methods:
                    print "Method {} is delegate method of protocol {}. ".format(imeth_name, self.delegate_protocol)
                    self.analyzer.analyze_function(start_addr=imeth_ea,
                                                   init_args=self.delegate_protocol_methods[m.group('selector')][1: -1])

    def construct_delegate_meths(self):
        p = Protocol.protocol_indexed_by_name[self.delegate_protocol]
        for meth_type in ['class_meths', 'opt_class_meths', 'inst_meths', 'opt_inst_meths']:
            for meth, t in p.__dict__[meth_type].items():
                self.delegate_protocol_methods[meth] = parser1(t)




