__author__ = 'gjy'
import commands
import re

def find_Imports(f):
    cmd = "objdump -t {}".format(f)
    output = commands.getstatusoutput(cmd)
    sym_tb = output[1]
    imported_symbols = []
    for s in sym_tb.split("\n"):
        imported = re.search('0000000000000000[\sw]+\*UND\*\s(?P<import>_.*)', s)
        if imported and imported.group('import'):
            print imported.group('import')
            imported_symbols.append(imported.group('import'))
    print "total: {}".format(len(imported_symbols))
    return imported_symbols


a = find_Imports("../samples/AlipaySDK_arm64")
print "-------------------------------"
t = find_Imports("../samples/TencentOpenAPI_arm64")

print "Common symbols:"
for i in a:
    if i in t:
        print i
