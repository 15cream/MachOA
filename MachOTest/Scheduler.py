from MachOTask import MachOTask
from SecCheck.sensitiveData import SensitiveData
import Data.CONSTANTS as CTS


class Scheduler:

    def __init__(self):
        self.analyzer = MachOTask('../samples/CsdnPlus_arm64', store=True, visualize=False)

    def sensitive_data_analyze(self):
        sd = SensitiveData(receiver='SmLocation', selector='getGeoLocation')
        sd.find_data_as_ret_value()
        self.analyzer.to_be_analyzed.update(set(sd.as_ret_value.keys()))
        while self.analyzer.to_be_analyzed:
            for f in list(self.analyzer.to_be_analyzed):
                ret_set = self.analyzer.analyze_function(start_addr=f)
                if ret_set:
                    for ret in ret_set:
                        if 'Marked' in str(ret):
                            sdt = SensitiveData(func_ea=f)
                            print sdt
                self.analyzer.to_be_analyzed.remove(f)
        self.analyzer.clear()

    def simple_analyze(self):
        self.analyzer.analyze_function(start_addr=0x10011AAFC)
        # self.analyzer.analyze_class(classname='CNBBSViewController')


sd_scheduler = Scheduler()
# sd_scheduler.sensitive_data_analyze()
sd_scheduler.simple_analyze()
