from Data.CONSTANTS import BLOCK_LIMIT


def block_excess(angr_project, start_addr):
    cfg = angr_project.analyses.CFGAccurate(keep_state=True, starts=[start_addr, ], call_depth=0)
    print '{} BLOCKS DETECTED in {}.'.format(len(cfg._nodes), hex(start_addr))
    if len(cfg._nodes) > BLOCK_LIMIT:
        print 'SKIPPED(TOO MUCH BLOCKS): ', hex(start_addr)
        return True
    return False
