__author__ = 'gjy'


class IVar():

    ivars = dict()

    def __init__(self, ptr, name=None, _class=None, type=None):
        self.ptr = ptr
        self.name = name
        self._class = _class
        self.type = type

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

