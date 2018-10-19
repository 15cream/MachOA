import archinfo
import pickle
from types import *


class OCClass:

    class_set = []
    imported_class_set = []
    binary_class_set = dict()  # INDEXED BY CLASS_INFO_ADDRESS (the value stored in classref)
    classes_indexed_by_ref = dict()
    classes_indexed_by_name = dict()
    classes_indexed_by_meth = dict()  # meth_imp - > [meth_name, class_obj]
    classes_indexed_by_selector = dict()

    def __init__(self, classref, imported=False, name=None):

        self.class_meths = dict()
        self.instance_meths = dict()
        self.classref_addr = classref
        self.class_addr = None
        self.name = name if imported else None
        self.imported = imported
        self.meta_class_addr = None

    @staticmethod
    def retrieve(classref=None, classname=None):
        if classref:
            if classref in OCClass.classes_indexed_by_ref:
                return OCClass.classes_indexed_by_ref[classref]
            else:
                print "NO SUCH CLASS_REF"
        if classname:
            if classname in OCClass.classes_indexed_by_name:
                return OCClass.classes_indexed_by_name[classname]
            else:
                print "NO SUCH CLASS_NAME"

    def build(self, state):
        if self.imported:
            bv = state.solver.BVV(self.classref_addr, 64).reversed
            state.memory.store(self.classref_addr, bv)
            OCClass.imported_class_set.append(self.classref_addr)
        else:
            self.class_addr = state.memory.load(self.classref_addr, 8, endness=archinfo.Endness.LE)
            class_data_addr = state.memory.load(self.class_addr + 32, 8, endness=archinfo.Endness.LE)
            self.name = state.mem[class_data_addr+24].deref.string.concrete
            self.resolve_methods_imp(state, self.class_addr, instance_m=True)
            self.resolve_ivar(state, self.class_addr, instance_m=True)
            self.meta_class_addr = state.memory.load(self.class_addr, 8, endness=archinfo.Endness.LE)
            self.resolve_methods_imp(state, self.meta_class_addr, class_m=True)
            OCClass.binary_class_set[state.solver.eval(self.class_addr)] = self

        OCClass.classes_indexed_by_name[self.name] = OCClass.classes_indexed_by_ref[self.classref_addr] = self
        OCClass.class_set.append(self.__dict__)
        print hex(self.classref_addr), self.name

    def resolve_methods_imp(self, state, addr, instance_m=None, class_m=None):
        meths = dict()
        classname = self.name
        formatstr = "-[{} {}]" if instance_m else "+[{} {}]"
        info = state.memory.load(addr + 32, 8, endness=archinfo.Endness.LE)
        meth_list_addr = state.memory.load(info + 32, 8, endness=archinfo.Endness.LE)
        meth_list_info = state.mem[meth_list_addr].methlist
        entry_size = state.solver.eval(meth_list_info.entrysize.resolved)
        count = state.solver.eval(meth_list_info.count.resolved)

        for meth_addr in range(meth_list_addr+8, meth_list_addr+8+entry_size*count, entry_size):
            meth = state.mem[meth_addr].meth
            meth_name = formatstr.format(classname, meth.name.deref.string.concrete)
            meth_imp = state.solver.eval(meth.imp.resolved)
            meths[meth_imp] = meth_name
            if meth_imp not in OCClass.classes_indexed_by_meth:
                OCClass.classes_indexed_by_meth[meth_imp] = [meth_name, self]
        if instance_m:
            self.instance_meths = meths
        elif class_m:
            self.class_meths = meths

    def resolve_ivar(self, state, addr, instance_m=None, class_m=None):
        classname = self.name
        info = state.memory.load(addr + 32, 8, endness=archinfo.Endness.LE)
        ivars = state.memory.load(info + 48, 8, endness=archinfo.Endness.LE)
        ivars_info = state.mem[ivars].ivarlist
        entry_size = state.solver.eval(ivars_info.entrysize.resolved)
        count = state.solver.eval(ivars_info.count.resolved)

        for ivar_ea in range(ivars+8, ivars+8+entry_size*count, entry_size):
            ivar = state.mem[ivar_ea].meth
            # ptr
            # meth_name
            # type =

    @staticmethod
    def dump(db):
        output = open(db, 'wb')
        pickle.dump(OCClass.class_set, output)
        output.close()

    @staticmethod
    def unpack(state, db):
        input = open(db, 'rb')
        class_set = pickle.load(input)
        for c in class_set:
            cd = OCClass(c['classref_addr'])
            if type(c['class_addr']) is not NoneType:
                cd.class_addr = state.solver.eval(c['class_addr'])
            else:
                cd.class_addr = None
            if type(c['meta_class_addr']) is not NoneType:
                cd.meta_class_addr = state.solver.eval(c['meta_class_addr'])
            else:
                cd.meta_class_addr = None
            cd.name = c['name']
            cd.imported = c['imported']
            cd.class_meths = c['class_meths']
            cd.instance_meths = c['instance_meths']
            if cd.imported:
                OCClass.imported_class_set.append(cd)
                bv = state.solver.BVV(cd.classref_addr, 64).reversed
                state.memory.store(cd.classref_addr, bv)
            else:
                OCClass.binary_class_set[cd.class_addr] = cd
            OCClass.classes_indexed_by_ref[cd.classref_addr] = cd
            OCClass.classes_indexed_by_name[cd.name] = cd
            meths = dict(cd.instance_meths.items() + cd.class_meths.items())
            for meth in meths:
                meth_name = meths[meth]
                OCClass.classes_indexed_by_meth[meth] = [meth_name, cd]
                selector = meth_name.split(' ')[-1].strip(']')
                if selector in OCClass.classes_indexed_by_selector:
                    OCClass.classes_indexed_by_selector[selector].append(cd)
                else:
                    OCClass.classes_indexed_by_selector[selector] = [cd, ]
        input.close()


