import os
import re

def checked(root):
    checked = []
    for f in os.listdir(root):
        m = re.search('(?P<addr>[a-f0-9xX]+).+', f)
        if m:
            checked.append(m.group('addr'))
        else:
            print 'RE ERROR', f
    return checked

# print "\n".join(checked('../results/WeiBo_arm64'))
