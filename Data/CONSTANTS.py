import angr

LAZY_BIND_F = 0
MSGSEND = 1
INTERINVOKE = 1
#
INVOKEFS = "Context:{} {}\nDepth:{}\nInvoke:{} {}\n{}"

# about instance variable
IVAR_FORMAT = "{class_name}{var_name}{var_typr}"

IPC = False

dispatch = ['_dispatch_async', '_dispatch_once']

RECEIVERS = ['NSURL', 'NSURLConnection', 'CFStream', 'NSStream', 'NSURLSession', 'NSMutableURLRequest']
SELECTORS = ['initWithRequest:delegate:startImmediately:', ]
msgSendSuper = ['_objc_msgSendSuper2', '_objc_msgSendSuper']
msgSends = ['_objc_msgSend', '_objc_msgSendSuper2']
objc_symbols = ['_objc_retainAutoreleasedReturnValue',
                '_objc_retainAutoreleaseReturnValue',
                '_objc_autoreleaseReturnValue',
                '_objc_retain',
                '_objc_release',
                '_objc_retainAutorelease',
                ]
angr.types.define_struct('struct methlist{int entrysize; int count;}')
angr.types.define_struct('struct meth{char* name; char* type; long imp;}')
angr.types.define_struct('struct ivarlist{int entrysize; int count;}')
angr.types.define_struct('struct ivar{long ptr; char* name; char* type; int align; int size;}')
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

REC_SEL_RET = {
    (None, 'alloc'): None,
    ('UIDevice', 'currentDevice'): 'UIDevice',
    (None, 'init'): None,
    ('UIScreen', 'mainScreen'): 'UIScreen',

}