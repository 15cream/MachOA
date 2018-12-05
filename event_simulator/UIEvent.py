from Data.OCClass import OCClass
from Data.Symbol import ImportedClass
from Data.classes.UIResponder import UIResponder


class UIEvent:

    def __init__(self, analyzer):
        self.analyzer = analyzer

    def simulate(self):
        symbol = ImportedClass('_OBJC_CLASS_$_UILabel', self.analyzer)
        symbol.analyze_usage()
        for occlass in symbol.sub_binary_class:  # occlass subclass UIViewController, could act as UIResponder
            responder = UIResponder(occlass, self.analyzer)
            responder.simulate()







