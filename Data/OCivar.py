__author__ = 'gjy'


class IVar():

    ivars = dict()

    def __init__(self, ptr, name=None, _class=None, type=None):
        self.ptr = ptr
        self.name = name
        self._class = _class
        self.type = type
        self.accessors = {
            'get': [],
            'set': [],
        }

    def add_to_ivars(self):
        if self not in IVar.ivars:
            IVar.ivars[self.ptr] = self

    def to_dict(self):
        return {
            'name': self.name,
            'class': self._class,
            'type': self.type,
            'ptr': self.ptr,
        }

    def add_set_accessor(self, state):
        print 'Here.'

