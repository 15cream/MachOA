# coding=utf-8
# https://developer.apple.com/documentation/foundation/nsdata?language=objc
# A static byte buffer in memory.


class NSData:

    writings = [
        'writeToFile:atomically:',
        'writeToFile:options:error:',
        'writeToURL:atomically:',
        'writeToURL:options:error:'
    ]

    def __init__(self):
        pass

    @staticmethod
    def is_writing_action(message=None, rec=None, sel=None):
        if message and message.selector in NSData.writings:
            return True
        if sel in NSData.writings:
            return True
        return False

