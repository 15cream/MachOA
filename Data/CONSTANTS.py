import angr

LAZY_BIND_F = 0
MSGSEND = 1
INTERINVOKE = 1
#
INVOKEFS = "Context:{} {}\nDepth:{}\nInvoke:{} {}\n{}"

# about instance variable
IVAR_FORMAT = "{classname}{var_name}{var_typr}"

IPC = False

dispatch = ['_dispatch_async', '_dispatch_once']

RECEIVERS = ['NSURL', 'NSURLConnection', 'CFStream', 'NSStream', 'NSURLSession', 'NSMutableURLRequest']
SELECTORS = ['initWithRequest:delegate:startImmediately:', ]
msgSendSuper = ['_objc_msgSendSuper2', '_objc_msgSendSuper']
msgSends = ['_objc_msgSend']
objc_symbols = ['_objc_retainAutoreleasedReturnValue',
                '_objc_retainAutoreleaseReturnValue',
                '_objc_autoreleaseReturnValue',
                '_objc_retain',
                '_objc_release',
                '_objc_retainAutorelease',
                ]
angr.types.define_struct('struct methlist{int entrysize; int count;}')
angr.types.define_struct('struct meth{char* name; long type; long imp;}')