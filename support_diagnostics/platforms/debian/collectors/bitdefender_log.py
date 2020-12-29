import glob
import gzip
from os.path import dirname, basename, isfile, join

from support_diagnostics import Collector,CollectorResult

class BitdefenderLogCollector(Collector):
    id = "bitdefender_log"

    """
    Get Bit Defender log entries
    """
    def collect(self):
        results = []
        for log in glob.glob(join(dirname("/var/log/"), "bdamserver.*")):
            result = CollectorResult(self, log)
            if log.endswith(".gz"):
                log_file = gzip.open(log, "rb")
                result.output = [line.decode("ascii").rstrip() for line in log_file.readlines()]
            else:
                log_file = open(log, "r")
                result.output = [line.rstrip() for line in log_file.readlines()]
            log_file.close()
            results.append(result)

        return results