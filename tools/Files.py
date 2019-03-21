import os
import re


def checked(root):
    checked = dict()
    for f in os.listdir(root):
        m = re.search('(?P<addr>[a-f0-9xX]+).+', f)
        if m:
            checked[m.group('addr')] = os.path.join(root, f)
        else:
            print 'RE ERROR', f
    return checked

# print "\n".join(checked('../results/WeiBo_arm64'))
