import subprocess
from os.path import dirname, basename, isfile, join

from support_diagnostics import Collector,CollectorResult

class SystemCollector(Collector):
    version_file_name = "/usr/share/untangle/lib/untangle-libuvm-api/VERSION"

    """
    Get NGFW system information
    """
    def collect(self):
        results = []

        # Product version
        result = CollectorResult(self, "version")
        file = open(SystemCollector.version_file_name, "r")
        result.output = [line.rstrip() for line in file.readlines()]
        file.close()
        results.append(result)

        # Hardware architecture
        result = CollectorResult(self, "arch")
        proc = subprocess.Popen(['uname', '-m'], stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            result.output = [line.decode("ascii").rstrip()]
        results.append(result)

        return results