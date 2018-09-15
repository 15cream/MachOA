from angrTest.atask import ATask
import time
from visualize.CallGraph import CallGraph
from tools.utils import *

def analyzer_test():
    analyzer = ATask('/home/gjy/Desktop/MachOA/samples/ToGoProject', store=True, visualize=False)
    # analyzer.analyze_function(0x10033B544)
    # analyzer.analyze_function(0x1003E1328)
    analyzer.analyze_function(0x1001F9E00)

    print time.strftime("-END-%Y-%m-%d %H:%M:%S", time.localtime())

    # print find_refs(refed='AlipaySDK')


def meth_call_visualize_graph(f):
    cg = CallGraph(f)
    cg.build()
    cg.output('/home/gjy/Desktop/MachOA/visualize/cgs/rsa.pdf')


def class_ref_test():
    print "\n".join(find_refs(refed='AlipaySDK'))
    build_web(from_class='AlipaySDK')


# class_ref_test()
analyzer_test()
# meth_call_visualize_graph('/home/gjy/Desktop/MachOA/xmls/ToGoProject/+[WeChatApiUtil isAppInstalledWithCatchException:].xml')