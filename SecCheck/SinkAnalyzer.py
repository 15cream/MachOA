import re


class SinkAnalyzer:

    def __init__(self, msg):
        self.msg = msg

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

    def is_setter(self):

        return
