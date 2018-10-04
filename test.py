from angrTest.atask import ATask
import time
from visualize.CallGraph import CallGraph
from tools.utils import *

def analyzer_test():
    analyzer = ATask('/home/gjy/Desktop/MachOA/samples/ToGoProject', store=True, visualize=False)
    # analyzer.analyze_function(0x10033B544)
    # analyzer.analyze_function(0x1003E1328)
    # analyzer.analyze_function(0x10049CEA0)
    # analyzer.analyze_function(0x1006C9C10)
    # analyzer.analyze_function(0x10071D158)
    # analyzer.analyze_function(0x1007C4964)  # -[BPushBindRequest HttpBody]
    # analyzer.analyze_function(0x100722488)
    # analyzer.analyze_class(classname='TDATUtility')
    # analyzer.analyze_function(0x10079CEF4)
    # analyzer.analyze_function(0x1006F3518)
    # analyzer.analyze_function(0x10018F458)
    # analyzer.analyze_function(0x10027ED34)
    # analyzer.analyze_function(0x010027EB1C)
    # analyzer.analyze_function(0x010027ED34)
    # analyzer.analyze_function(0x10028D1C8)
    # analyzer.analyze_function(0x10033C308)
    # analyzer.analyze_function(0x10032C0DC)
    # analyzer.analyze_function(0x10046C8FC)
    # analyzer.analyze_function(0x10046B3E0)
    analyzer.analyze_function(0x10032BFA0)
    # analyzer.analyze_function(0x1003255E4)
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