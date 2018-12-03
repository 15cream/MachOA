import idc
import idautils
import idaapi
from binary import Binary
from Rules import Rule

print 'Parsing Binary Data...'
p = Binary()
p.parse()
print 'Parsing Done. '

r = Rule()
r.set_bin_data(p.get_data())
r.receiver_str = 'QQApiMessage'
r.selector_str = 'encodeWithCoder:'
result = r.analyze()




# r.receiver_str = 'TMVideoUploadManager'
# r.selector_str = 'buildFilename'
# r.selector_str = 'buildHTTPBodyForPreUpload'





