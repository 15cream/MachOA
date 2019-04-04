import os
import re

from Data.CONSTANTS import BLOCK_LIMIT


def block_excess(angr_project, start_addr):
    cfg = angr_project.analyses.CFGAccurate(keep_state=True, starts=[start_addr, ], call_depth=0)
    print '{} BLOCKS DETECTED in {}.'.format(len(cfg._nodes), hex(start_addr))
    if len(cfg._nodes) > BLOCK_LIMIT:
        print 'SKIPPED(TOO MUCH BLOCKS): ', hex(start_addr)
        return True
    return False


def add_value_to_list_in_dict_with_key(value, key, dict):
    if key in dict:
        dict[key].append(value)
    else:
        dict[key] = [value, ]


def checked_existence_in_dir(root):
    checked = dict()
    for f in os.listdir(root):
        m = re.search('(?P<addr>[a-f0-9xX]+).+', f)
        if m:
            checked[m.group('addr')] = os.path.join(root, f)
        else:
            print 'RE ERROR', f
    return checked


def symbol_resolved(symbol):
    m = re.search('\((?P<data_type>.+)<(?P<instance_type>.+):(?P<ptr>.+)>\)(?P<name>.+)', symbol)
    if m:
        data_type = m.group('data_type').encode('UTF-8')
        instance_type = m.group('instance_type').encode('UTF-8')
        ptr = int(m.group('ptr').encode('UTF-8').strip('L'), 16)
        return data_type, instance_type, ptr
    return None, None, None