__author__ = 'gjy'


class Delegate():
    def __init__(self, msg):
        self.msg = msg

    def isDelegateAccessor(self):
        if 'elegate' in self.msg.selector:
            print self.msg.g.nodes[self.msg.node]['dp']
            return True
