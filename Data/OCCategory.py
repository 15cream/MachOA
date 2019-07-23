# coding=utf-8
import archinfo
from OCClass import OCClass
from OCFunction import OCFunction


class Category:

    category_indexed_by_data_EA = dict()
    category_indexed_by_name = dict()

    def __init__(self, ea):
        self.ea = ea  # in catlist
        self.data_ea = None  # __objc2_category data in __objc_const
        self.name = None
        self._class = None
        self.oc_class = None
        self.inst_meths = dict()
        self.class_meths = None
        self.props = None
        self.prots = None

    @staticmethod
    def analyze_catlist(binary, state):
        catlist = binary.get_segment_by_name('__DATA').get_section_by_name('__objc_catlist')
        for ea in range(catlist.min_addr, catlist.max_addr, 8):
            category = Category(ea)
            category.analyze(state)
            Category.category_indexed_by_name[category.name] = category
            Category.category_indexed_by_data_EA[category.data_ea] = category

    def analyze(self, state):
        self.data_ea = state.mem[self.ea].long.concrete
        category = state.mem[self.data_ea].category
        self.name = category.name.deref.string.concrete
        self._class = category._class.concrete  # 未绑定情况下此处为０
        if self._class in OCClass.classes_indexed_by_ref:
            self.oc_class = OCClass.classes_indexed_by_ref[self._class]
            self.oc_class.categories.append(self.data_ea)

        self.inst_meths = self.analyze_meth(state, category.inst_meths.concrete, inst=True)
        self.class_meths = self.analyze_meth(state, category.class_meths.concrete)
        self.prots = category.prots.concrete
        self.props = category.props.concrete

    def analyze_meth(self, state, meth_list_addr, inst=False):
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
                meth_type = meth.type.deref.string.concrete
                methlist_dict[meth_name] = (meth_imp, meth_type)
                if self.oc_class:
                    f = OCFunction(imp=meth_imp, rec=self.oc_class.name, sel=meth_name,
                                   prot=meth_type,
                                   meth_type='-' if inst else '+')
                meth_addr += entry_size

        return methlist_dict
