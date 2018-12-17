__author__ = 'gjy'
import commands
from Data.OCivar import IVar
from Data.OCClass import OCClass
from Data.OCFunction import OCFunction
from Data.CONSTANTS import *
from tools.oc_type_parser import *
import pickle


class SensitiveData:

    xrefs = dict()

    def __init__(self, data_type=None, receiver=None, selector=None):
        """
        Give a plain data_type string.
        :param data_type:
        :return:
        """
        self.receiver = receiver
        self.selector = selector
        self.type = receiver if not data_type else data_type
        self.as_ret = self.as_ret()

    @staticmethod
    def init(xref_pkl):
        f = open(xref_pkl)
        SensitiveData.xrefs = pickle.load(f)
        f.close()

    def as_x0(self):
        """
        The X0 of instance method call is the instance.
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
        for ptr, ivar in IVar.ivars.items():
            if str_to_type(self.type) == ivar.type:
                print hex(ptr)

    def as_ret(self):
        """
        [UIDevice currentDevice] return the UIDevice instance.
        Find the [UIDevice currentDevice] invoke.
        :return:
        """
        fs = OCFunction.meth_indexed_by_sel[self.selector] if self.selector in OCFunction.meth_indexed_by_sel else None
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

        return inter_ctx

    def as_para(self):
        """
        The first parameter of 'locationManager:didUpdateLocations:' is CLLocationManager.
        Analyze the 'locationManager:didUpdateLocations:' method.
        :return:
        """
        pass

    @staticmethod
    def build_xrefs_from_file(dbf):
        f = open(dbf)
        SensitiveData.xrefs = pickle.load(f)
        f.close()

    @staticmethod
    def ask_for_xrefs(ea, data_type):
        """

        :param ea:
        :param data_type: class, sel, ivar
        :return:
        """
        if data_type in SensitiveData.xrefs and ea in SensitiveData.xrefs[data_type]:
            return SensitiveData.xrefs[data_type][ea]
        else:
            return {}

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