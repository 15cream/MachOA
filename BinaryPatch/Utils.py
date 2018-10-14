from Data.MachO import MachO
from Data.OCFunction import OCFunction
from Data.OCClass import OCClass

import re


def retrieve_f(name=None, imp=None):
    results = {'type': None,
               'receiver': None,
               'selector': None,
               'imp': None,
               'complete_methname': None}
    if name:
        m = re.search('(?P<type>[-+]?)\[(?P<receiver>\S+?) (?P<selector>[\w:]+)\]', name)
        if m:
            results['type'] = type = m.group('type')
            results['receiver'] = receiver = m.group('receiver')
            results['selector'] = selector = m.group('selector')
        else:
            print "???"
            return results
        if receiver in OCClass.classes_indexed_by_name:
            pass
        elif selector in OCClass.classes_indexed_by_selector:
            possible_classes = OCClass.classes_indexed_by_selector[selector]
            # for c in possible_classes:
            #     if c.name in receiver:
            #         results['receiver'] = c.name
            #         name = "{}[{} {}]".format(type, receiver, selector)
            if len(possible_classes) == 1:
                c = possible_classes.pop()
                results['receiver'] = c.name
                name = "{}[{} {}]".format(type, receiver, selector)
        if name in OCFunction.function_symbols:
            results['imp'] = OCFunction.function_symbols[name]
            results['complete_methname'] = name
        else:
            for s, imp in OCFunction.function_symbols.items():
                if name in s:
                    results['imp'] = imp
                    results['complete_methname'] = s
                    break
    return results


def resolve_context(ea):
    # find which function this ea resides in
    for f in sorted(MachO.pd.macho.lc_function_starts, reverse=True):
        if ea >= f:
            break
    return f


