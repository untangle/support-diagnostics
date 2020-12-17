import glob
from os.path import dirname, basename, isfile, join

from support_diagnostics import Collector,CollectorResult

class AptSourcesCollector(Collector):
    id = "os_update_sources"

    """
    Get apt sources
    """
    def collect(self):
        results = []
        modules = glob.glob(join(dirname("/etc/apt/"), "*.list"))
        for module in glob.glob(join(dirname("/etc/apt/sources.list.d/"), "*.list")):
            modules.append(module)

        for module in modules:
            result = CollectorResult(self, module)
            module_file = open(module, "r")
            result.output = [line.rstrip() for line in module_file.readlines()]
            module_file.close()
            results.append(result)

        return results