import idc
import idautils
import idaapi
from binary import Binary
from Rules import Rule

print 'Parsing Binary Data...'
p = Binary()
p.parse()
print 'Paring Done. '

r = Rule()
r.set_bin_data(p.get_data())
r.receiver_str = 'WXOMTAEvent'
r.selector_str = 'toJsonString'
result = r.analyze()




# r.receiver_str = 'TMVideoUploadManager'
# r.selector_str = 'buildFilename'
# r.selector_str = 'buildHTTPBodyForPreUpload'





