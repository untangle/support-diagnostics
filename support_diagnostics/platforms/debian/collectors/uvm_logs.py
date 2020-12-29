import glob
import gzip
from os.path import dirname, basename, isfile, join

from support_diagnostics import Collector,CollectorResult

class UvmLogCollector(Collector):
    id = "uvm_log"

    """
    Get uvm log entries
    """
    def collect(self):
        results = []
        for log in glob.glob("/var/log/uvm/*"):
            if "packages.log" in log:
                continue
            print(".", end='', flush=True)
            result = CollectorResult(self, log)
            if log.endswith(".gz"):
                result.output = []
                log_file = gzip.open(log, "rb")
                try:
                    for line in log_file.readlines():
                        result.output.append(line.decode("ascii").rstrip())
                except:
                    # !! Would be better to have a method or super class to read and handle both gz and non gz
                    pass
            else:
                log_file = open(log, "r")
                result.output = [line.rstrip() for line in log_file.readlines()]
            log_file.close()
            results.append(result)

        return results