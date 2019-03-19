# coding=utf-8
import angr
import pickle

current_ctx = None

LAZY_BIND_F = 0
MSGSEND = 1
INTERINVOKE = 1

# 执行树中的调用节点格式
INVOKEFS = "Context:{} {}\nDepth:{}\nInvoke:{} {}\n{}"
# 执行树中的返回节点格式
RETFS = "Return {} at {}"

# about instance variable
IVAR_FORMAT = "{class_name}{var_name}{var_typr}"

# Inter-procedural analysis
IPC = False
CS_LIMITED = True

# Sensitive Data Analysis
SDA = True

# ...
# 当开启时，采取从stub->stub_helper->analyze_lazy_bind_symbol的方案
# 当关闭时，采取在EXIT EVENT 里对lazy_bind_symbol进行解析
# 经过对比实验发现，= ,  =  效率上基本没差
STUB_HOOK = True


dispatch = ['_dispatch_async', '_dispatch_once']
msgSendSuper = ['_objc_msgSendSuper2', '_objc_msgSendSuper']
msgSends = ['_objc_msgSend', '_objc_msgSendSuper2']
performSelectors = ['performSelector:withObject:afterDelay:', ]
retSymbols = []
objc_symbols = ['_objc_retainAutoreleasedReturnValue',
                '_objc_retainAutoreleaseReturnValue',
                '_objc_autoreleaseReturnValue',
                '_objc_retain',
                '_objc_release',
                '_objc_retainAutorelease',
                ]
getProperty = [
    '_objc_getProperty',
]

setProperty = [
    '_objc_setProperty_nonatomic_copy',
    '_objc_setProperty_atomic'
]

RECEIVERS = ['NSURL', 'NSURLConnection', 'CFStream', 'NSStream', 'NSURLSession', 'NSMutableURLRequest']
SELECTORS = ['initWithRequest:delegate:startImmediately:', ]

angr.types.define_struct('struct methlist{int entrysize; int count;}')
angr.types.define_struct('struct meth{char* name; char* type; long imp;}')
angr.types.define_struct('struct ivarlist{int entrysize; int count;}')
angr.types.define_struct('struct ivar{long ptr; char* name; char* type; int align; int size;}')
angr.types.define_struct('struct proplist{int entrysize; int count;}')
angr.types.define_struct('struct prop{char* name; char* attr;}')
angr.types.define_struct('struct prot{long isa; char* name; long prots; long inst_meths; long class_meths; '
                         'long opt_inst_meths; long opt_class_meths; long inst_props; int cb; int flags; long methtype;}')


instance_types = {
    'PARA': 'passed_in_as_parameter',
    'REC': 'as_receiver',
    'RET': 'as_ret_value',
    'IVAR': 'ret_as_ivar'
}
FORMAT_INSTANCE = '({data_type}<{instance_type}:{ptr}>){name}'
FORMAT_IVAR_OFFSET = '(<ea:{ptr}>)IVAR_OFFSET'
FORMAT_COMMON_DATA = '(unknown<ea:{ptr}>)COMMON_DATA'
FORMAT_BSS_DATA = '(unknown<ea:{ptr}>)BSS_DATA'

# INSTANCE_RANDOM_RANGE
IRR = 1000

# Receiver type can be used to infer ret_type, imp
REC_SEL_RET = {
    (None, 'alloc'): None,
    (None, 'sharedInstance'): None,
    (None, 'init'): None,
    (None, 'UUIDString'): 'UUIDString',
    ('UIDevice', 'currentDevice'): 'UIDevice',
    ('UIScreen', 'mainScreen'): 'UIScreen',
    ('UIDevice', 'identifierForVendor'): 'NSUUID',
    ('UIPasteboard', 'generalPasteboard'): 'UIPasteboard',
    ('NSMutableDictionary',  'dictionaryWithCapacity:'): 'NSMutableDictionary',
    ('NSMutableDictionary',  'addEntriesFromDictionary:'): 'NSMutableDictionary',
    ('NSKeyedArchiver', 'archivedDataWithRootObject:'): 'NSData',
}

Rules = {
    'Location': [
        {
            'Receiver': '<CLLocationManagerDelegate>',
            'Selector': 'locationManager:didUpdateLocations:',
            'Arguments': ['CLLocationManager', 'NSArray<CLLocation *>'],
            'RET': None,
            'Description': 'Tells the delegate that new location rule is available.'
        }
    ],
    'ID': [
        {
            'Receiver': 'UIDevice',
            'Selector': 'identifierForVendor',
            'Arguments': None,
            'RET': 'NSUUID',
            'Description': 'An alphanumeric string that uniquely identifies a device to the app’s vendor.'
        }
    ]
}


class Xrefs:
    database = None

    def __init__(self, fp):
        f = open(fp)
        Xrefs.database = pickle.load(f)
        f.close()

    @staticmethod
    def ask_for_xrefs(ea, ea_type):
        """
        :param ea:
        :param ea_type: class, sel, ivar
        :return: the xrefs already parsed by IDA.
        """
        if ea_type in Xrefs.database and ea in Xrefs.database[ea_type]:
            return Xrefs.database[ea_type][ea]
        else:
            return {}


# XREF_DB = Xrefs.database
