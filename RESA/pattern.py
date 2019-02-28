from scenario import *
import commands


class Sequence:

    def __init__(self, s):
        self.ori_seq = s
        self.expr = ''

    def symbolize(self):
        for item in self.ori_seq:
            if item in Symbols:
                self.expr += '{} -1 '.format(Symbols.index(item))
            else:
                self.expr += '{} -1 '.format(len(Symbols))
                Symbols.append(item)
        self.expr += "-2 \n"

    def dump(self):
        f.write(self.expr)


Symbols = []
f = open('/home/gjy/Desktop/EMining/dbs.txt', 'w')
# extractor = ScenarioExtractor(seeds=[Seed(dt='NSURL')],
#                               dir='../../results/ScenarioTest/total_etrees/')
extractor = ScenarioExtractor(seeds=[Seed(rec='UIDevice', sel='identifierForVendor'),
                                     Seed(rec='UIDevice', sel='performSelector:')],
                              dir='../../results/ScenarioTest/total_etrees/')
# extractor = ScenarioExtractor(seeds=[Seed(dt='NSURL')],
#                               dir='../../results/ScenarioTest/total_etrees/')

extractor.run()
for scenario in extractor.scenarios_for_mining:
    ori_seq = []
    for index, des in sorted(scenario.sub_trace.items(), key=lambda item: item[0]):
        ori_seq.append(des)
        s = Sequence(ori_seq)
        s.symbolize()
        s.dump()
f.close()

(status, output) = commands.getstatusoutput(
    'cd /home/gjy/Desktop/EMining; java -jar spmf.jar run VMSP dbs.txt output.txt 0.5%')  # CM-SPADE  BIDE+  VMSP

result = open('/home/gjy/Desktop/EMining/output.txt', 'r')
for line in result.readlines():
    # print line
    pattern = line.split('#')[0].split()
    if len(pattern) > 4:
        sup = line.split('#')[1]
        for symbol in pattern:
            if symbol == '-1':
                continue
            print Symbols[int(symbol)]
        print sup, '\n'
result.close()
# print '\n'.join(Symbols)

