from MachOTask import MachOTask
from SecCheck.seed import API


class Scheduler:

    def __init__(self):
        self.analyzer = MachOTask('../../samples/ToGoProject', store=True, visualize=False)

    def sensitive_data_analyze(self):
        print 'Good Luck = , = '

        # seed = API(receiver='GtGbdNetworkRequest', selector='sendNetworkRequest:completionHandler:', ea=4299487688)
        # cs = CallString.construct_according_to_a_seed(seed)[-1]
        # Analyzer.current_cs_limited = cs
        # #     cs.pprint()
        # for api in cs.stack[1:]:
        #     print api.ea
        #     self.analyzer.analyze_function(start_addr=api.ea)
        # self.analyzer.analyze_function(start_addr=cs.stack[-1].ea)

        seed = API(receiver='GXCommonUtils', selector='createGtRuleRegisterId')
        # seed.find_calls(gist='SEL')
        seed.find_calls()
        for func in seed.calls:
            self.analyzer.analyze_function(start_addr=func)

        # sd2 = ADT('NSURLSession')
        # sd2.find_occurrences()
        # for func in sd2.occurrences:
        #     self.analyzer.analyze_function(start_addr=func)

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
        #                     pass  # Sensitive rule escaped here.
        #         self.analyzer.to_be_analyzed.remove(f)
        self.analyzer.clear()

    def simple_analyze(self):

        # self.analyzer.analyze_class(classname='WXOMTAGCDAsyncSocket')
        # self.analyzer.analyze_class(classname='SmLocation')
        # print self.analyzer.analyze_function(start_addr=0x10078DD40)
        self.analyzer.analyze_function(start_addr=0x100465E18)


sd_scheduler = Scheduler()
# sd_scheduler.sensitive_data_analyze()
sd_scheduler.simple_analyze()

