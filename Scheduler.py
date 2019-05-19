from MachOTask import MachOTask
from SecCheck.seed import API, ADT
from SecCheck.callString import CallString
import sys


class Scheduler:

    def __init__(self, bin_path):
        self.analyzer = MachOTask(bin_path, store=True, visualize=False)

    def sensitive_data_analyze(self, receiver=None, selector=None, adt=None, gist=None):
        print 'Good Luck = , = '

        # seed = API(receiver='GtGbdNetworkRequest', selector='sendNetworkRequest:completionHandler:', ea=4299487688)
        # cs = CallString.construct_according_to_a_seed(seed)[-1]
        # Analyzer.current_cs_limited = cs
        # #     cs.pprint()
        # for api in cs.stack[1:]:
        #     print api.eacreateGtRuleRegisterId
        #     self.analyzer.analyze_function(start_addr=api.ea)
        # self.analyzer.analyze_function(start_addr=cs.stack[-1].ea)

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

        # s_funcs = set()
        # for func in sd.as_ret_value:
        #     if sd.as_ret_value[func]['rec']:
        #         s_funcs.add(func)
        #
        # if len(sd.as_ret_value) < 100:
        #     self.analyzer.to_be_analyzed.update(sd.as_ret_value.keys())
        # else:
        #     self.analyzer.to_be_analyzed.update(s_funcs)

        # self.analyzer.tobe_analyzed.update(sd2.occurrences)
        #
        # while self.analyzer.to_be_analyzed:
        #     for f in list(self.analyzer.to_be_analyzed):
        #         if not sd.as_ret_value[f]['rec']:
        #             continue
        #         ret_set = self.analyzer.analyze_function(start_addr=f)
        #         if ret_set:
        #             for ret in ret_set:
        #                 if 'Marked' in str(ret):
        #                     pass  # Sensitive rule_id escaped here.
        #         self.analyzer.to_be_analyzed.remove(f)
        self.analyzer.clear()

    def simple_analyze(self, ea):

        # self.analyzer.analyze_class(classname='WXOMTAGCDAsyncSocket')
        # self.analyzer.analyze_class(classname='SmLocation')
        # print self.analyzer.analyze_function(start_addr=0x10078DD40)
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

sd_scheduler = Scheduler('../samples/yellowpage_arm64')
api = API(receiver='MGSwipeButtonsView ', selector='handleClick:fromExpansion:')
# api = API(receiver='UIDevice', selector='identifierForVendor')
cs = CallString.construct_according_to_a_seed(api)
print len(cs)
# for call_string in cs:
#     sd_scheduler.analyzer.analyze_with_cs(call_string)
sd_scheduler.analyzer.analyze_with_cs(cs[2])

# sd_scheduler.simple_analyze(0x01000BE1D4)
# sd_scheduler.simple_analyze(0x1000E2F0C)