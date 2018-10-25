import idc
import idautils
import idaapi
# idaapi.require('Rules')
# idaapi.require('preprocess')
from Rules import Rule
from binary import Binary
import sys

# idaapi.autoWait()

p = Binary()
p.run()

r = Rule()
r.set_bin_data(p.get_data())
r.receiver_str = 'UIDevice'
r.selector_str = 'identifierForVendor'
result = r.analyze()

# idc.Exit(0)


# r.receiver_str = 'TMVideoUploadManager'
# r.selector_str = 'buildFilename'
# r.selector_str = 'buildHTTPBodyForPreUpload'





