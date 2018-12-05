from Data.OCClass import OCClass
from Data.MachO import MachO


class Symbol(object):

    def __init__(self, name, analyzer):
        self.name = name
        self.type = None
        self.analyzer = analyzer


class ImportedClass(Symbol):

    def __init__(self, name, analyzer):
        super(ImportedClass, self).__init__(name, analyzer)
        self.sub_binary_class = []

    def analyze_usage(self):
        symbol = self.analyzer.macho.get_symbol(self.name)
        if symbol and len(symbol) == 1:
            for bind_xref in symbol[0].bind_xrefs:
                seg = self.analyzer.pd.query_segment(bind_xref)
                if seg == 'class_ref':
                    pass  # as classref
                elif seg == 'objc_const':
                    pass  # category
                elif seg == 'classdata':
                    # as superclass
                    if bind_xref - 8 in OCClass.binary_class_set:
                        self.sub_binary_class.append(OCClass.binary_class_set[bind_xref - 8])
                else:
                    print seg


