import archinfo
from OCivar import IVar
from OCFunction import OCFunction


class OCClass:
    class_set = []
    imported_class_set = []
    binary_class_set = dict()  # INDEXED BY CLASS_INFO_ADDRESS (the value stored in class_ref)
    classes_indexed_by_ref = dict()
    classes_indexed_by_name = dict()
    classes_indexed_by_meth = dict()  # meth_imp - > [meth_name, class_obj]
    classes_indexed_by_selector = dict()

    def __init__(self, classref, imported=False, name=None):

        self.imported = imported
        self.classref_addr = classref
        self.meta_class_addr = None
        self.superclass_addr = None
        self.class_addr = None
        self.name = name if imported else None
        self.class_meths = dict()
        self.instance_meths = dict()
        self.ivars = None
        self.prots = dict()

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
            self.meta_class_addr = state.memory.load(self.class_addr, 8, endness=archinfo.Endness.LE)
            self.superclass_addr = state.memory.load(self.class_addr + 8, 8, endness=archinfo.Endness.LE)

            class_data_addr = state.memory.load(self.class_addr + 32, 8, endness=archinfo.Endness.LE)
            if state.solver.eval(class_data_addr) % 8 != 0:
                print class_data_addr, 'ERROR'
                return None

            self.name = state.mem[class_data_addr + 24].deref.string.concrete
            self.resolve_methods_imp(state, self.class_addr, instance_m=True)
            self.resolve_methods_imp(state, self.meta_class_addr, class_m=True)
            self.resolve_ivar(state, self.class_addr)
            self.resolve_prots(state, self.class_addr)

            OCClass.binary_class_set[state.solver.eval(self.class_addr)] = self

        OCClass.classes_indexed_by_name[self.name] = OCClass.classes_indexed_by_ref[self.classref_addr] = self
        OCClass.class_set.append(self.__dict__)
        print hex(self.classref_addr), self.name

    def resolve_methods_imp(self, state, addr, instance_m=None, class_m=None):
        meths = dict()
        info = state.memory.load(addr + 32, 8, endness=archinfo.Endness.LE)
        meth_list_addr = state.memory.load(info + 32, 8, endness=archinfo.Endness.LE)

        if state.solver.eval(meth_list_addr) != 0:
            meth_list_info = state.mem[meth_list_addr].methlist
            entry_size = state.solver.eval(meth_list_info.entrysize.resolved)
            count = state.solver.eval(meth_list_info.count.resolved)

            meth_addr = meth_list_addr + 8
            for i in range(0, count):
                meth = state.mem[meth_addr].meth
                f = OCFunction(imp=state.solver.eval(meth.imp.resolved),
                               rec=self.name,
                               sel=meth.name.deref.string.concrete,
                               prot=meth.type.deref.string.concrete,
                               meth_type='-' if instance_m else '+')

                meths[f.imp] = f.expr
                if f.imp not in OCClass.classes_indexed_by_meth:
                    OCClass.classes_indexed_by_meth[f.imp] = [f.expr, self]
                meth_addr += entry_size

        if instance_m:
            self.instance_meths = meths
        elif class_m:
            self.class_meths = meths

    def resolve_ivar(self, state, addr):
        ivarlist = []
        info = state.memory.load(addr + 32, 8, endness=archinfo.Endness.LE)
        ivars = state.memory.load(info + 48, 8, endness=archinfo.Endness.LE)
        if state.solver.eval(ivars):
            ivars_info = state.mem[ivars].ivarlist
            entry_size = state.solver.eval(ivars_info.entrysize.resolved)
            count = state.solver.eval(ivars_info.count.resolved)

            ivar_ea = ivars + 8
            for i in range(0, count):
                ivar = state.mem[ivar_ea].ivar
                ptr = state.solver.eval(ivar.ptr.resolved)
                name = ivar.name.deref.string.concrete
                type = ivar.type.deref.string.concrete
                ivar_ea += entry_size
                ivaro = IVar(ptr, name=name, type=type, _class=self.name)
                ivarlist.append(ivaro)
        self.ivars = ivarlist

    def resolve_prots(self, state, objc2_class):
        objc2_class_ro = state.memory.load(objc2_class + 32, 8, endness=archinfo.Endness.LE)
        objc2_prot_list = state.memory.load(objc2_class_ro + 0x28, 8, endness=archinfo.Endness.LE)

        if state.solver.eval(objc2_prot_list) != 0:
            count = state.solver.eval(state.memory.load(objc2_prot_list, 8, endness=archinfo.Endness.LE))
            for i in range(0, count):
                offset = (i + 1) * 8
                objc2_prot = state.memory.load(objc2_prot_list + offset, 8, endness=archinfo.Endness.LE)
                prot = state.mem[objc2_prot].prot
                prot_name = prot.name.deref.string.concrete
                self.prots[prot_name] = objc2_prot

