from angrTest.analyzer import Analyzer
import time
from visualize.CallGraph import CallGraph
from tools.utils import *

def analyzer_test():
    analyzer = Analyzer('../samples/Mobike', store=True, visualize=False)
    # analyzer.analyze_class_dds(classname='BaiduMobStat')
    # analyzer.analyze_class(classref=0x1000c39d4)
    # analyzer.analyze_function(0x100042FA4)
    analyzer.analyze_bin()

    print time.strftime("-END-%Y-%m-%d %H:%M:%S", time.localtime())

    # print find_refs(refed='AlipaySDK')
    # analyzer.analyze_function(start_addr=0x1000C232C)
    # analyzer.analyze_function(name="+[TGHttpManager queryStringFromParameters:]")

def meth_call_visualize_graph():
    cg = CallGraph('/home/gjy/Desktop/MachOA/xmls/+[TGHttpManager TGEncryptPOSTWithURLString:parameters:name:type:showLoading:showError:loginInvalid:success:failure:].xml')
    cg.build()
    cg.output('/home/gjy/Desktop/MachOA/visualize/cgs/+[TGHttpManager TGEncryptPOSTWithURLString:parameters:name:type:showLoading:showError:loginInvalid:success:failure:].pdf')


def class_ref_test():
    print "\n".join(find_refs(refed='AlipaySDK'))
    build_web(from_class='AlipaySDK')


# class_ref_test()
analyzer_test()