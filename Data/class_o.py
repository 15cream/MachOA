import archinfo
import pickle


class class_o:

    class_set = []
    imported_class_set = []
    binary_class_set = dict()  # INDEXED BY CLASS_INFO_ADDRESS (the value stored in classref)
    classrefs = dict()
    classnames = dict()

    def __init__(self, classref, imported=False, name=None):

        self.class_meths = []
        self.instance_meths = []
        self.classref_addr = classref
        self.class_addr = None
        self.name = name if imported else None
        self.imported = imported

    def build(self, state):
        if self.imported:
            bv = state.solver.BVV(self.classref_addr, 64).reversed
            state.memory.store(self.classref_addr, bv)
            class_o.imported_class_set.append(self.classref_addr)
        else:
            self.class_addr = state.memory.load(self.classref_addr, 8, endness=archinfo.Endness.LE)
            class_data_addr = state.memory.load(self.class_addr + 32, 8, endness=archinfo.Endness.LE)
            self.name = state.mem[class_data_addr+24].deref.string.concrete
            # self.resolve_methods_imp(state, self.class_addr, instance_m=True)
            self.meta_class_addr = state.memory.load(self.class_addr, 8, endness=archinfo.Endness.LE)
            # self.resolve_methods_imp(state, self.meta_class_addr, class_m=True)
            class_o.binary_class_set[state.solver.eval(self.class_addr)] = self

        class_o.classnames[self.name] = class_o.classrefs[self.classref_addr] = self
        class_o.class_set.append(self.__dict__)
        # print "class {} has been resolved.".format(self.name)

    def resolve_methods_imp(self, state, addr, instance_m=None, class_m=None):
        meths = []
        classname = self.name
        formatstr = "-[{} {}]" if instance_m else "+[{} {}]"
        info = state.memory.load(addr + 32, 8, endness=archinfo.Endness.LE)
        meth_list = state.memory.load(info + 32, 8, endness=archinfo.Endness.LE)
        meth_addr = meth_list + 8
        meth_list = state.mem[meth_list].methlist
        entry_size = state.solver.eval(meth_list.entrysize.resolved)
        count = state.solver.eval(meth_list.count.resolved)
        for i in range(0, count):
            meth = state.mem[meth_addr].meth
            meth_name = meth.name.deref.string.concrete
            meth_imp = state.solver.eval(meth.imp.resolved)
            # print "{} [ {} {} ]".format(hex(meth_imp), classname, meth_name)
            meth_addr += entry_size
            meths.append([meth_imp, formatstr.format(classname, meth_name)])
        if instance_m:
            self.instance_meths = meths
        elif class_m:
            self.class_meths = meths

    @staticmethod
    def dump():
        output = open('classes.pkl', 'wb')
        pickle.dump(class_o.class_set, output)
        output.close()




