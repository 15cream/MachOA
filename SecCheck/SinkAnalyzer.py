import re


class SinkAnalyzer:

    def __init__(self, msg):
        self.msg = msg

    def sensitive_data_as_parameter(self):
        if self.msg.selector.args:
            for arg in self.msg.selector.args:
                expr = arg.expr
                m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', expr)
                if m:
                    if 'Marked' in m.group('data_type'):
                        return True
        return False

    def is_setter(self):

        return
