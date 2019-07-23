# coding=utf-8


class CryptoResults:

    results_pool = dict()

    def __init__(self, ctx, ea, symbol=None):
        self.id = "{}_{}".format(ctx, ea)  # hex(caller_ctx)_hex(ea)
        if self.id not in CryptoResults.results_pool:
            CryptoResults.results_pool[self.id] = self
        else:
            print "ERROR: at CryptoResults.__init__"
        self.ctx = ctx
        self.ea = ea
        self.symbol = symbol
        self.use_ECB = False
        self.insufficient_rounds = False
        self.iv = None
        self.key = None
        self.salt = None


    @staticmethod
    def query_result(id):
        if id in CryptoResults.results_pool:
            return CryptoResults.results_pool[id]
        else:
            return None

    def pprint(self):
        print "-------------------------------------------"
        print "当前加密调用发生在地址{}，位于方法{}内".format(hex(self.ea), hex(self.ctx))
        print "符号：{}".format(self.symbol)
        print "使用ECB模式：{}".format(self.use_ECB)
