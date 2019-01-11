import angr

LAZY_BIND_F = 0
MSGSEND = 1
INTERINVOKE = 1
#
INVOKEFS = "Context:{} {}\nDepth:{}\nInvoke:{} {}\n{}"

# about instance variable
IVAR_FORMAT = "{class_name}{var_name}{var_typr}"

# Inter-procedural analysis
IPC = True

# Sensitive Data Analysis
SDA = False
SDA_IPC = False

dispatch = ['_dispatch_async', '_dispatch_once']
msgSendSuper = ['_objc_msgSendSuper2', '_objc_msgSendSuper']
msgSends = ['_objc_msgSend', '_objc_msgSendSuper2']
retSymbols = []
objc_symbols = ['_objc_retainAutoreleasedReturnValue',
                '_objc_retainAutoreleaseReturnValue',
                '_objc_autoreleaseReturnValue',
                '_objc_retain',
                '_objc_release',
                '_objc_retainAutorelease',
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
    ('UIDevice', 'currentDevice'): 'UIDevice',
    (None, 'init'): None,
    ('UIScreen', 'mainScreen'): 'UIScreen',
    ('UIDevice', 'identifierForVendor'): 'Marked_NSUUID',
    ('UIPasteboard', 'generalPasteboard'): 'Marked_UIPasteboard',
    ('NSMutableDictionary',  'dictionaryWithCapacity:'): 'NSMutableDictionary',
    ('NSMutableDictionary',  'addEntriesFromDictionary:'): 'NSMutableDictionary',
}

XREF_DB = None

