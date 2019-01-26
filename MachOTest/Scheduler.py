from MachOTask import MachOTask
from SecCheck.sensitiveData import SensitiveData
import Data.CONSTANTS as CTS


class Scheduler:

    def __init__(self):
        self.analyzer = MachOTask('../samples/DoubanRadio_arm64', store=True, visualize=False)

    def sensitive_data_analyze(self):
        sd = SensitiveData(receiver='UIDevice', selector='identifierForVendor')
        sd.as_ivar()
        sd.find_data_as_ret_value()

        s_funcs = set()
        for func in sd.as_ret_value:
            if sd.as_ret_value[func]['rec']:
                s_funcs.add(func)

        if len(sd.as_ret_value) < 100:
            self.analyzer.to_be_analyzed.update(sd.as_ret_value.keys())
        else:
            self.analyzer.to_be_analyzed.update(s_funcs)

        while self.analyzer.to_be_analyzed:
            for f in list(self.analyzer.to_be_analyzed):
                if not sd.as_ret_value[f]['rec']:
                    continue
                ret_set = self.analyzer.analyze_function(start_addr=f)
                if ret_set:
                    for ret in ret_set:
                        if 'Marked' in str(ret):
                            sdt = SensitiveData(func_ea=f)
                            print sdt
                self.analyzer.to_be_analyzed.remove(f)
        self.analyzer.clear()

    def simple_analyze(self):
        self.analyzer.analyze_function(start_addr=0x1000115D8)
        # self.analyzer.analyze_class(classname='WXOMTAGCDAsyncSocket')
        # self.analyzer.analyze_class(classname='SmLocation')


sd_scheduler = Scheduler()
sd_scheduler.sensitive_data_analyze()
# sd_scheduler.simple_analyze()

