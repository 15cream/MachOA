class XRef:

    def __init__(self, addr):
        self.frm = addr
        self.to = dict()

    def insert_xref(self, to_ea):
        pass