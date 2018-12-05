import re


class UIResponder:

    # An abstract interface for responding to and handling events.
    def __init__(self, occlass, analyzer):
        self.handlers = {'touchesBegan:withEvent:': {'args': ['NSSet<UITouch *>', '@UIEvent']},
                         'touchesMoved:withEvent:': {'args': ['NSSet<UITouch *>', '@UIEvent']},
                         'touchesEnded:withEvent:': {'args': ['NSSet<UITouch *>', '@UIEvent']},
                         'touchesCancelled:withEvent:': {'args': ['NSSet<UITouch *>', '@UIEvent']},
                         'touchesEstimatedPropertiesUpdated:': {'args': ['NSSet<UITouch *>']},
                         'motionBegan:withEvent:': {'args': ['UIEventSubtype', '@UIEvent']},
                         'motionEnded:withEvent:': {'args': ['UIEventSubtype', '@UIEvent']},
                         'motionCancelled:withEvent:': {'args': ['UIEventSubtype', '@UIEvent']},
                         'pressesBegan:withEvent:': {'args': ['NSSet<UIPress *>', '@UIPressesEvent']},
                         'pressesChanged:withEvent:': {'args': ['NSSet<UIPress *>', '@UIPressesEvent']},
                         'pressesEnded:withEvent:': {'args': ['NSSet<UIPress *>', '@UIPressesEvent']},
                         'pressesCancelled:withEvent:': {'args': ['NSSet<UIPress *>', '@UIPressesEvent']},
                         'remoteControlReceivedWithEvent:': {'args': ['@UIEvent']},
                         }
        self.occlass = occlass
        self.analyzer = analyzer

    def simulate(self):
        for imeth_ea, imeth_name in self.occlass.instance_meths.items():
            m = re.search('(?P<type>[-+]?)\[(?P<receiver>\S+?) (?P<selector>[\w:]+)\]', imeth_name)
            if m:
                selector = m.group('selector')
                if selector in self.handlers:
                    self.analyzer.analyze_function(start_addr=imeth_ea, init_args=self.handlers[selector]['args'])


class UIApplication(UIResponder):

    # The centralized point of control and coordination for apps running in iOS.
    def __init__(self):
        pass


class UIViewController(UIResponder):

     # An object that manages a view hierarchy for your UIKit app.
    def __init__(self):
        pass


class UIView(UIResponder):

    # An object that manages the content for a rectangular area on the screen.
    def __init__(self):
        pass