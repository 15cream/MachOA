import re


def parser1(string):
    ret_type = string.split('@0:8')[0]
    para_types = string.split('@0:8')[1]
    ret_type = re.split('\d+', ret_type)[0: -1]
    para_types = re.split('\d+', para_types)[0: -1]
    ret_type.extend(para_types)
    for t in ret_type:
        t.replace('"', '')
    return ret_type


# UIEvent to @"UIEvent"
def str_to_type(str):
    return '@"{}"'.format(str)


# @"UIEvent" to UIEvent
def type_to_str(type_str):
    return type_str.strip('@').strip('"')


