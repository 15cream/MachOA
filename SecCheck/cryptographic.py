# coding=utf-8
from tools.common import symbol_resolved

ERROR1 = 1  # Rule 1: Use ECB mode for encryption, 针对CCCrypt()和CCCryptorCreate()函数
ERROR2 = 2  # Rule 2: Use a non-random IV for CBC encryption，针对CCCrypto()、CCCryptorCreate()、CCCryptorCreateWithMode()
ERROR3 = 3  # Rule 3: Use constant encryption keys.
ERROR4 = 4  # Rule 4: Do not use constant salts for PBE.
ERROR5 = 5  # Rule 5: Do not use fewer than 1,000 iterations for PBE.
ERROR6 = 6  # Rule 6: Do not use static seeds to seed SecureRandom.


class CryptoChecker:

    crypt_funcs = ['_CCCrypt', '_CCCryptorCreate', '_CCCryptorCreateWithMode', '_CCKeyDerivationPBKDF']

    def __init__(self):
        pass

    @staticmethod
    def is_ECB(options):
        options = int(options.expr)
        if options == 0:  # default: CBC
            return 0
        elif options == 1:  # kCCOptionPKCS7Padding
            return 0
        elif options == 2:  # kCCOptionECBMode
            return ERROR1
        elif options == 3:  # kCCOptionPKCS7Padding | kCCOptionECBMode
            return ERROR1
        return 0

    @staticmethod
    def is_non_random_iv(iv):
        # 前提是使用CBC模式，然后检查该iv是否是常量或是一个可预测的值？如果iv没有被特别指定，会以全0填充，也不安全
        # 如果IV是由CCRandomGenerateBytes()或SecRandomCopyBytes()生成的则认为安全
        print "该IV变量为：{}".format(iv.expr)
        if iv.expr == '0':
            return ERROR2
        return 0

    @staticmethod
    def is_constant_key(key):
        # 检查该key是否为常量，如是则返回ERROR3
        if key.concrete:
            pass
        else:
            data_type, instance_type, ptr = symbol_resolved(key.expr)
            print '该key为变量：{}'.format(key.expr)


    @staticmethod
    def check_salt(salt):
        # 检查盐值是否为常量，若是返回 ERROR4
        print salt

    @staticmethod
    def check_rounds(rounds):
        # 检查迭代次数是否大于1000
        if rounds > 1000:
            return 0
        else:
            return ERROR5



    @staticmethod
    def check(graphview, node, args):
        print '————————————————————————————————————————————————————————————'
        print ">>> 当前检测的函数调用：\n{}".format(node)
        print '>>> 检测结果:'
        node_data = graphview.g.nodes[node]
        if node_data['des'] == '_CCCrypt':
            # Stateless, one-shot encrypt or decrypt operation,
            # This basically performs a sequence of CCCryptorCreate(), CCCryptorUpdate(), CCCryptorFinal(), CCCryptorRelease()
            # 1,2,3,
            options = args[2]
            iv = args[5]
            key = args[3]
            if CryptoChecker.is_ECB(options):
                print 'ERROR: USE ECB MODE FOR ENCRYPTION.'
            elif CryptoChecker.is_non_random_iv(iv):
                print 'ERROR: USE A NON-RANDOM IV FOR CBC ENCRYPTION.'
            if CryptoChecker.is_constant_key(key):
                print 'ERROR: USE CONSTANT ENCRYPTION KEYS.'

        elif node_data['des'] == '_CCCryptorCreate':
            # 1,2,3,
            options = args[2]
            iv = args[5]
            key = args[3]
            print 'Check'
        elif node_data['des'] == '_CCCryptorCreateWithMode':
            # 2,3
            iv = args[4]
            key = args[5]
            pass
        elif node_data['des'] == '_CCKeyDerivationPBKDF':
            # 3,4,5
            pwd = args[1]
            salt = args[3]
            rounds = args[6]





