from Data.OCClass import OCClass
from Data.Symbol import ImportedClass
from Data.classes.UIResponder import UIResponder


class UIEvent:

    def __init__(self, analyzer):
        self.analyzer = analyzer

    def simulate(self):
        uiresponders = ['_OBJC_CLASS_$_UILabel', '_OBJC_CLASS_$_UIView', '_OBJC_CLASS_$_UIViewController']
        for rs in uiresponders:
            symbol = ImportedClass(rs, self.analyzer)
            symbol.analyze_usage()
            for occlass in symbol.sub_binary_class:  # occlass subclass UIViewController, could act as UIResponder
                responder = UIResponder(occlass, self.analyzer)
                responder.simulate()







