__author__ = 'gjy'
import commands
from Data.OCivar import IVar
from Data.OCClass import OCClass
from Data.OCFunction import OCFunction
from tools.oc_type_parser import *
import pickle


class SensitiveData:
    xrefs = dict()
    ssData = None

    def __init__(self, data_type=None, receiver=None, selector=None, ivar_name=None, func_ea=None):
        """
        Give a plain data_type string.
        :param data_type:
        :return:
        """
        self.receiver = receiver
        self.selector = selector
        self.type = receiver if not data_type else data_type
        self.ivar_name = ivar_name
        self.as_ret_value = None
        if func_ea and func_ea in OCFunction.oc_function_set:
            f = OCFunction.oc_function_set[func_ea]
            self.receiver = f.receiver
            self.selector = f.selector

        # If you want do multi-type sensitive database analysis, you could use a list.
        SensitiveData.ssData = self

    @staticmethod
    def init(xref_pkl):
        f = open(xref_pkl)
        SensitiveData.xrefs = pickle.load(f)
        f.close()

    def as_x0(self):
        """
        The X0 of instance method call is the specified type instance.
        :return: method_dict {function_ea: function_name}
        """
        class_set = set()  # OCClass instances
        method_dict = dict()
        for ea, oc_class in OCClass.binary_class_set.items():
            if self.type == oc_class.name:
                class_set.add(oc_class)
            # Add superclass
            # Add category
        for c in class_set:
            method_dict.update(c.instance_meths)
        return method_dict

    def as_ivar(self):
        """
        Some ivar typed UIDevice. @"UITextField", @"NSUUID"
        :return: The direct reference context and where getter was invoked.
        """
        ivars = set()
        if self.ivar_name:
            for ptr, ivar in IVar.ivars.items():
                if ivar.name == self.ivar_name:
                    ivars.add(ptr)
        elif self.type:
            for ptr, ivar in IVar.ivars.items():
                if str_to_type(self.type) == ivar.type:
                    ivars.add(ptr)
        print ivars
        for ptr in ivars:
            ivar = IVar.ivars[ptr]
            ivar.parse_accessors()
            setter_ctx = SensitiveData(receiver=ivar._class, selector=ivar.setter).find_data_as_ret_value()
            getter_ctx = SensitiveData(receiver=ivar._class, selector=ivar.getter).find_data_as_ret_value()

    def find_data_as_ret_value(self):
        """
        [UIDevice currentDevice] return the UIDevice instance.
        Find where the [UIDevice currentDevice] invokes.
        :return:
        """
        inter_ctx = dict()
        r_ctx = SensitiveData.ask_for_xrefs(self.receiver, 'class')
        s_ctx = SensitiveData.ask_for_xrefs(self.selector, 'selector')

        # Where the selector occurs
        for ea, f in s_ctx.items():
            if f not in inter_ctx:
                inter_ctx[f] = {
                    'sel': [ea, ],
                    'rec': []
                }
            else:
                inter_ctx[f]['sel'].append(ea)

        # If receiver occurs in the context where selector occurs also.
        if r_ctx:
            for ea, f in r_ctx.items():
                if f in inter_ctx:
                    inter_ctx[f]['rec'].append(ea)

        self.as_ret_value = inter_ctx
        return inter_ctx

    def as_para(self, rec, selector, arg_index):
        """
        The first parameter of 'locationManager:didUpdateLocations:' is CLLocationManager.
        Analyze the 'locationManager:didUpdateLocations:' method.
        :return:
        """
        pass

    @staticmethod
    def ask_for_xrefs(ea, ea_type):
        """
        :param ea:
        :param ea_type: class, sel, ivar
        :return: the xrefs already parsed by IDA.
        """
        if ea_type in SensitiveData.xrefs and ea in SensitiveData.xrefs[ea_type]:
            return SensitiveData.xrefs[ea_type][ea]
        else:
            return {}

    def record(self):
        """
        Record the sensitive database usage.
        :return:
        """

    @staticmethod
    def build_xrefs_from_file(dbf):
        f = open(dbf)
        SensitiveData.xrefs = pickle.load(f)
        f.close()

    # deprecated
    def find_callstack_via_IDA(self):
        f = open('/Users/gjy/Documents/git_workspace/MachOA/samples/angr_ida_channel', 'wb')
        for ptr, ivar in IVar.ivars.items():
            if r'@"UITextField"' == ivar.type:
                f.write('{}\n'.format(hex(ptr)))
        f.close()

        cmd = '{} -OIDAPython:{} {}'.format(
            '/Applications/IDA_Pro_7.0/IDA_Pro_7.0/ida.app/Contents/MacOS/ida64',
            '/Users/gjy/Documents/git_workspace/MachOA/IDAScripts/find_callstack.py',
            '/Users/gjy/Documents/git_workspace/MachOA/samples/AppJobber_arm64_bak.i64')

        commands.getstatusoutput(cmd)

