import re


class SinkAnalyzer:
    tainted_receiver = {
        'NSMutableDictionary': [
            'addEntriesFromDictionary:'
        ]
    }

    def __init__(self, msg, ssData):
        self.msg = msg
        self.ssData = ssData

    def sensitive_data_as_parameter(self):
        # Mark the return value if marked data used as parameter.
        if self.msg.selector.args:
            for arg in self.msg.selector.args:
                expr = arg.expr
                try:
                    m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', expr)
                    if m:
                        if 'Marked' in m.group('data_type'):
                            return True
                except TypeError as e:
                    print 'TypeError: ', e
        return False

    def sensitive_data_as_receiver(self):
        # Mark the return value if receiver is marked.
        if 'Marked' in self.msg.receiver.data.expr:
            return True

    def sensitive_data_as_ret(self):
        """
        Check if ssData's returned as ret_value, if so, find the possible caller.
        :return:
        """
        if self.msg.selector.expr == self.ssData.selector and self.msg.receiver.oc_class and \
                self.msg.receiver.oc_class.name == self.ssData.receiver:
            return True

    def receiver_tainted(self):
        if self.msg.receiver.oc_class and self.msg.receiver.oc_class.name in SinkAnalyzer.tainted_receiver:
            if self.msg.selector.expr in SinkAnalyzer.tainted_receiver[self.msg.receiver.oc_class.name]:
                return True
