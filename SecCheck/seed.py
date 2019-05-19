# coding=utf-8
from Data.OCivar import IVar
from Data.OCClass import OCClass
from Data.OCFunction import OCFunction
from Data.CONSTANTS import *
from tools.oc_type_parser import *
from MachOTask import MachOTask

SEL_LIMIT = 20


class API:

    def __init__(self, receiver=None, selector=None, func=None, ea=None):
        if receiver and selector:
            self.is_oc_function = True
            self.receiver = receiver
            self.selector = selector
            self.description = '[{} {}]'.format(self.receiver, self.selector)
        else:
            self.is_oc_function = False
            self.function = func
            self.description = self.function

        self.ea = ea
        self.calls = set()

    def find_selector_last_occurs(self, context):
        last_ea = 0
        for ea, ctx in Xrefs.ask_for_xrefs(self.selector, 'selector').items():
            if ctx == context:
                if ea > last_ea:
                    last_ea = ea
        return last_ea

    def find_calls(self, gist='MSG'):
        self.calls = set()
        if self.is_oc_function:
            s_ctx = Xrefs.ask_for_xrefs(self.selector, 'selector')
            s_ctx = set(s_ctx.values())
            if gist == 'SEL':  # 仅凭借selector来寻找可疑caller
                self.calls = s_ctx
            else:
                r_ctx = ADT(self.receiver).find_occurrences()
                if gist == 'MSG':
                    self.calls = r_ctx & s_ctx
                elif gist == 'ADJ':
                    if r_ctx & s_ctx:
                        self.calls = r_ctx & s_ctx
                    elif len(list(s_ctx)) < SEL_LIMIT:
                        self.calls = s_ctx
            return self.calls
        else:
            if self.ea in OCFunction.meth_list and self.ea not in OCFunction.oc_function_set:
                sub_callers = Xrefs.ask_for_xrefs(self.ea, 'sub')
                if sub_callers:
                    self.calls = sub_callers
            return self.calls

    def find_calls_for_cs(self):
        ret = dict()
        if self.is_oc_function:
            s_ctx = Xrefs.ask_for_xrefs(self.selector, 'selector')
            for ea, ctx in s_ctx.items():
                if ctx not in ret:
                    ret[ctx] = {'sel': [ea]}
                else:
                    ret[ctx]['sel'].append(ea)
            r_ctx = ADT(self.receiver).find_occurrences()
            if r_ctx & set(ret.keys()):
                for ctx in ret.keys():
                    if ctx not in r_ctx:
                        ret.pop(ctx)
            elif len(list(s_ctx)) < SEL_LIMIT:
                pass
            else:
                ret = dict()

        elif self.ea in OCFunction.meth_list and self.ea not in OCFunction.oc_function_set:
            sub_callers = Xrefs.ask_for_xrefs(self.ea, 'sub')
            for call_site, ctx in sub_callers.items():
                if ctx not in ret:
                    ret[ctx] = [call_site]
                else:
                    ret[ctx].append(call_site)
        return ret



class ADT:

    def __init__(self, data_type):
        self.type = data_type
        self.generators = dict()
        self.occurrences = None
        self._as_class = None
        self._as_receiver = dict()
        self._as_ivar = None

    def add_generator(self, api):
        """
        当已知某API的返回值为当前数据类型时，将其添加到生成器中。
        :param api: API类对象
        :return:
        """
        if api.description not in self.generators:
            self.generators[api.description] = api

    def find_occurrences(self):
        """
        查找该数据可能出现的上下文，返回值为可疑上下文的起始地址的集合（可能为OC函数，也可能为subroutine）.
        包括该数据，该数据的父类、子类。
        :return: the function set (not that precisely)
        """
        if not self.occurrences:
            occurrences = set()
            occurrences.update(self.find_occurrences_single_type())
            occurrences.update(self.find_occurrences_up())
            occurrences.update(self.find_occurrences_down())
            self.occurrences = occurrences
        return occurrences

    def find_occurrences_up(self):
        # 查找当前类的父类（链）
        ret = set()
        if self.type in OCClass.classes_indexed_by_name:
            oc_class = OCClass.classes_indexed_by_name[self.type][0]
            if oc_class.superclass_addr and oc_class.superclass_addr in OCClass.binary_class_set:
                superclass = OCClass.binary_class_set[oc_class.superclass_addr]
                superclass_adt = ADT(superclass.name)
                ret.update(superclass_adt.find_occurrences_single_type())
                ret.update(superclass_adt.find_occurrences_up())
        return ret

    def find_occurrences_down(self):
        ret = set()
        if self.type in OCClass.classes_indexed_by_name:
            oc_class = OCClass.classes_indexed_by_name[self.type][0]
            if oc_class.class_addr in OCClass.class_and_subclasses:
                for subclass in OCClass.class_and_subclasses[oc_class.class_addr]:
                    subclass_adt = ADT(subclass)
                    ret.update(subclass_adt.find_occurrences_single_type())
                    ret.update(subclass_adt.find_occurrences_down())
        return ret

    def find_occurrences_single_type(self):
        """
        查找该数据可能出现的上下文，返回值为可疑上下文的起始地址的集合（可能为OC函数，也可能为subroutine）
        :return: the function set (not that precisely)
        """
        occurrences = set()
        occurrences.update(set(self.as_receiver().keys()))
        occurrences.update(set(self.as_class().values()))
        occurrences.update(self.as_ivar())
        return occurrences

    def as_class(self):
        """
        查当前数据类型的类引用，例如当需要定位NSURLSession对象时，可以先定位NSURLSession类引用所在代码。
        以及类方法。
        :return:  {ea: f}
        """
        if not self._as_class:
            self._as_class = Xrefs.ask_for_xrefs(self.type, 'class')
            for ea, oc_class in OCClass.binary_class_set.items():  # superclass, category ?
                if self.type == oc_class.name:
                    self._as_class.update(oc_class.class_meths)
        return self._as_class

    def as_receiver(self):
        """
        The X0 of instance method call is the specified type instance.
        对一个类的实例方法来说，其初始状态的X0寄存器中存放的为其所属类的对象。
        :return: method_dict {function_ea: function_name}
        """
        if not self._as_receiver:
            for ea, oc_class in OCClass.binary_class_set.items():  # superclass, category ?
                if self.type == oc_class.name:
                    self._as_receiver.update(oc_class.instance_meths)
        return self._as_receiver

    def as_ivar(self):
        """
        Some ivar typed UIDevice. @"UITextField", @"NSUUID"
        :return: The direct reference context and where accessors were invoked.
        """
        if not self._as_ivar:
            ctx = set()
            for ptr, ivar in IVar.ivars.items():
                if ivar.type == str_to_type(self.type):
                    xrefs_to_ivar = Xrefs.ask_for_xrefs(ptr, 'ivar')
                    ctx.update(set(xrefs_to_ivar.values()))
                    # ivar.parse_accessors()
                    # setter = API(receiver=ivar._class, selector=ivar.setter)
                    # ctx.update(setter.find_calls())
                    # getter = API(receiver=ivar._class, selector=ivar.getter)
                    # ctx.update(getter.find_calls())
            self._as_ivar = ctx
        return self._as_ivar

    def as_ret(self):
        """
        Statically you can check the prototype of each method.
        Dynamically you can find out some during the symbolic execution.
        THe same situation with as_para.
        :return:
        """
        if self.type in OCClass.classes_indexed_by_name:
            oc_class = OCClass.classes_indexed_by_name[self.type]
            if oc_class.class_meths:
                for f in oc_class.class_meths:
                    MachOTask.currentTask.analyze_function(start_addr=f)
                    print 'T'

    def as_para(self):
        """
        The first parameter of 'locationManager:didUpdateLocations:' is CLLocationManager.
        Analyze the 'locationManager:didUpdateLocations:' method.
        :return: the methods where this adt's used as parameter.
        """
        pass
