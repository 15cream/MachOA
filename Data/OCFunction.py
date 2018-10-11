# coding=utf-8
from OCClass import OCClass


class OCFunction:

    meth_list = []
    meth_data = dict()
    function_symbols = dict()

    def __init__(self):
        pass

    @staticmethod
    def build_meth_list(binary):

        OCFunction.meth_list = binary.lc_function_starts
        for meth_imp in OCFunction.meth_list:
            if meth_imp in OCClass.classes_indexed_by_meth:
                _name = OCClass.classes_indexed_by_meth[meth_imp][0]
                _class = OCClass.classes_indexed_by_meth[meth_imp][1]
            else:
                _name = 'sub_' + str(hex(meth_imp))
                _class = None
            if meth_imp not in OCFunction.meth_data:
                OCFunction.meth_data[meth_imp] = {'name': _name, 'class': _class}

            if _name not in OCFunction.function_symbols:
                OCFunction.function_symbols[_name] = meth_imp









