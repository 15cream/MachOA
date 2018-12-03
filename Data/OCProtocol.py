import archinfo


class Protocol:

    protocol_indexed_by_data_EA = dict()
    protocol_indexed_by_name = dict()

    def __init__(self, ea):
        self.ea = ea  # in protolist
        self.data_ea = None  # __objc2_prot data in __data
        self.name = None
        self.protos = None
        self.inst_meths = dict()
        self.class_meths = None
        self.opt_inst_meths = None
        self.opt_class_meths = None
        self.inst_props = None
        self.conformed_classes = None
        self.referred_properties = None
        self.methtype = None

    @staticmethod
    def analyze_protolist(binary, state):
        protolist = binary.get_segment_by_name('__DATA').get_section_by_name('__objc_protolist')
        for ea in range(protolist.min_addr, protolist.max_addr, 8):
            protocol = Protocol(ea)
            protocol.analyze(state)
            Protocol.protocol_indexed_by_name[protocol.name] = protocol
            Protocol.protocol_indexed_by_data_EA[protocol.data_ea] = protocol

    def analyze(self, state):
        self.data_ea = state.mem[self.ea].long.concrete
        prot = state.mem[self.data_ea].prot
        self.name = prot.name.deref.string.concrete
        self.methtype = prot.methtype.concrete
        self.inst_meths = self.analyze_meth(state, prot.inst_meths.concrete)
        self.class_meths = self.analyze_meth(state, prot.class_meths.concrete)
        self.opt_inst_meths = self.analyze_meth(state, prot.opt_inst_meths.concrete)
        self.opt_class_meths = self.analyze_meth(state, prot.opt_class_meths.concrete)

    def analyze_meth(self, state, meth_list_addr):
        methlist_dict = dict()
        if state.solver.eval(meth_list_addr) != 0:
            meth_list_info = state.mem[meth_list_addr].methlist
            entry_size = state.solver.eval(meth_list_info.entrysize.resolved)
            count = state.solver.eval(meth_list_info.count.resolved)

            meth_addr = meth_list_addr + 8
            for i in range(0, count):
                meth = state.mem[meth_addr].meth
                meth_name = meth.name.deref.string.concrete
                meth_imp = state.solver.eval(meth.imp.resolved)
                t = None
                try:
                    t = state.mem[self.methtype].deref.string.concrete
                    self.methtype += 8
                except Exception as e:
                    print e
                methlist_dict[meth_name] = t
                meth_addr += entry_size
        return methlist_dict
