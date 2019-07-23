# coding=utf-8
"""
对于解析过的方法体，我们记录其返回值
"""


class RetVal:

    def __init__(self, ctx):
        self.ctx = ctx  # ctx的返回值即当前对象
        self.limitation = None