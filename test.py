# coding=utf-8
import time
from MachOTask import MachOTask
from SecCheck.seed import API, ADT
from SecCheck.callString import CallString
from Results.call_sites import CallSite

analyzer = MachOTask('../samples/DamnVulnerableIOSApp', store=True, visualize=False)
analyzer.analyze_function(start_addr=0x01000D6AA4)
CallSite.restore()
css = CallString.construct_according_to_a_seed(API(receiver='NSManagedObjectContext', selector='save:'))
for cs in css:
    cs.pprint()
    # cs.set_limitation()
    # cs.run(analyzer)
CallSite.dump()



# print time.strftime("-END-%Y-%m-%d %H:%M:%S", time.localtime())
# analyzer.analyze_function(start_addr=0x010016F8AC)