from MachOTask import MachOTask
from SecCheck.seed import API, ADT
from SecCheck.callString import CallString
import sys


class Scheduler:

    def __init__(self, bin_path):
        self.analyzer = MachOTask(bin_path, store=True, visualize=False)

    def sensitive_data_analyze(self, receiver=None, selector=None, adt=None, gist=None):
        print 'Good Luck = , = '
        if adt:
            seed = ADT(adt)
            seed.find_occurrences()
            for func in seed.occurrences:
                self.analyzer.analyze_function(start_addr=func)
        elif receiver and selector:
            seed = API(receiver=receiver, selector=selector)
            seed.find_calls(gist=gist)
            for func in seed.calls:
                self.analyzer.analyze_function(start_addr=func)
                
        self.analyzer.clear()

    def simple_analyze(self, ea):
        self.analyzer.analyze_function(start_addr=ea)


# binary_path = sys.argv[1]
# sd_scheduler = Scheduler(binary_path)
# if len(sys.argv) == 3:
#     addr = eval(sys.argv[2])
#     sd_scheduler.simple_analyze(addr)
# elif len(sys.argv) == 5:
#     rec = sys.argv[2]
#     sel = sys.argv[3]
#     gist = sys.argv[4]
#     sd_scheduler.sensitive_data_analyze(receiver=rec, selector=sel, gist=gist)
