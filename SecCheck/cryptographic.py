# coding=utf-8
from tools.common import symbol_resolved
from RuntimePatch.ExecutionLimitation import CLimitation
from SecCheck.seed import API
from Results.crypto_results import CryptoResults
from Results.call_sites import CallSite

"""
以下规则参考论文？制定。
加密知识可以参考　https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60061/include/CommonCryptor.h.auto.html
"""
ERROR1 = 1  # Rule 1: Use ECB mode for encryption, 针对CCCrypt()和CCCryptorCreate()函数
ERROR2 = 2  # Rule 2: Use a non-random IV for CBC encryption，针对CCCrypto()、CCCryptorCreate()、CCCryptorCreateWithMode()
ERROR3 = 3  # Rule 3: Use constant encryption keys.
ERROR4 = 4  # Rule 4: Do not use constant salts for PBE.
ERROR5 = 5  # Rule 5: Do not use fewer than 1,000 iterations for PBE.
ERROR6 = 6  # Rule 6: Do not use static seeds to seed SecureRandom.

# 关于iv的检测：前提是使用CBC模式，然后检查该iv是否是常量或是一个可预测的值？如果iv没有被特别指定，会以全0填充，也不安全
# 如果IV是由CCRandomGenerateBytes()或SecRandomCopyBytes()生成的则认为安全


class CryptoChecker:

    crypt_funcs = ['_CCCrypt', '_CCCryptorCreate', '_CCCryptorCreateWithMode', '_CCKeyDerivationPBKDF']
    # crypt_funcs = ['_CCCrypt']
    valid = False
    analyzer = None

    def __init__(self):
        self.result = dict()

    @staticmethod
    def check_crypto(graphview, node, args):
        node_data = graphview.g.nodes[node]
        result = CryptoResults.query_result("{}_{}".format(node_data['context'], node_data['addr']))
        if not result:
            print '预期外的加密函数检测'
            return

        print "\n——————————————————————————————————————"
        print "发现加解密函数调用：{}".format(node)

        if node_data['des'] in ['_CCCrypt', '_CCCryptorCreate']:  # RULE 1,2,3,
            if args[0].expr == '1':
                return
            options = args[2]
            iv = args[5]
            key = args[3]
            if options.concrete and int(options.expr) >= 2:
                result.use_ECB = True
            else:
                result.iv = CryptoChecker.definition_analysis(graphview, node, iv)
            result.key = CryptoChecker.definition_analysis(graphview, node, key)

        elif node_data['des'] == '_CCCryptorCreateWithMode':  # RULE 2,3
            if args[0].expr == '1':
                return
            mode = args[1]
            iv = args[4]
            key = args[5]
            if mode.concrete and int(mode.expr) == 1:
                result.use_ECB = True
            else:
                result.iv = CryptoChecker.definition_analysis(graphview, node, iv)
            result.key = CryptoChecker.definition_analysis(graphview, node, key)

        elif node_data['des'] == '_CCKeyDerivationPBKDF':  # RULE 3,4,5
            pwd = args[1]
            salt = args[3]
            rounds = args[6]
            if rounds.concrete and int(rounds.expr) < 1000:
                result.insufficient_rounds = True
            result.pwd = CryptoChecker.definition_analysis(graphview, node, pwd)
            result.salt = CryptoChecker.definition_analysis(graphview, node, salt)

    @staticmethod
    def definition_analysis(graphview, node, val):
        """
        :param graphview:
        :param node:
        :param val:
        :return: 两种情况: True,　具体值；　False,　符号表示
        """
        if val.concrete:
            return True, val.expr
        else:
            rtype, imp, extra = graphview.definition_analysis(node, expr=val.expr)
            # 这里定值分析获得的是最后的结果，无论是具体值或是符号，backtrack里可以迭代
            if rtype == 'PARA':
                tracked_constants = CryptoChecker.backtrack(rtype, imp, extra)
                print ""
            elif rtype == 'RET_VALUE':
                tracked_constants = CryptoChecker.backtrack(rtype, imp, extra)
                print ""
            elif rtype == 'RAW':
                pass
            elif rtype == 'TODO':
                pass
            elif rtype is None:
                return False, val.expr

    @staticmethod
    def backtrack(rtype, imp, extra):
        """
        这个方法根据对加密函数检测的结果来向上追溯。
        :param criterion:
        :return:
        """
        # 如果依赖于一个方法调用的参数，我们追溯该方法的所有可能调用处，通过符号执行获得该处的参数值
        if rtype == 'PARA':
            sensitive_arg_index = extra
            callee = API(ea=imp)
            for ctx, ea in callee.find_calls_with_detail(gist='ADJ').items():
                cl = CLimitation(ctx, 'MSG', criterion=callee.selector)
                cl.calculate_valid_blocks_to_criterion()
                callsite = CallSite(callee.ea, ctx, criterion=(rtype, imp, extra))  # to be collected
                CryptoChecker.analyzer.analyze_function(start_addr=cl.ctx)
                constants, symbols = callsite.analyze_results_according_to_criterion()
                if constants:
                    return constants  # TODO 目前只是验证该符号执行系统可用，所以找到定值就收手
                else:
                    print "还需要另外一轮？"  # 此处应该继续调用backtrack，












