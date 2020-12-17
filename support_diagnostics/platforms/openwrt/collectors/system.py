import subprocess
from os.path import dirname, basename, isfile, join

from support_diagnostics import Collector,CollectorResult

class SystemCollector(Collector):
    os_release_file_name = "/etc/os-release"
    version_key = "VERSION"

    """
    Get NGFW system information
    """
    def collect(self):
        results = []

        # Product version
        result = CollectorResult(self, "version")
        file = open(SystemCollector.os_release_file_name, "r")
        for line in file.readlines():
            if line.startswith(SystemCollector.version_key):
                version = line.rstrip().split('=')[1].replace('"','')
                result.output = [version]
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