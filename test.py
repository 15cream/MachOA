from MachOTask import MachOTask
from SecCheck.seed import API, ADT
from SecCheck.callString import CallString
from RuntimePatch.ExecutionLimitation import CLimitation
import sys

analyzer = MachOTask('../samples/ToGoProject', store=True, visualize=False)
# cl = CLimitation(0x100447984, 'SEL', criterion='encryptUseDES:key:')
# cl.valid_blocks, cl.target_blocks = analyzer.calculate_valid_blocks_to_criterion(0x100447a38L, 0x100447984)
cl = CLimitation(0x100454038, 'EXTERNAL_C')
cl.valid_blocks, cl.target_blocks = analyzer.calculate_valid_blocks_to_criterion(0x100454124, cl.ctx)
CLimitation.currentLimitation = cl
analyzer.analyze_function(start_addr=cl.ctx)
