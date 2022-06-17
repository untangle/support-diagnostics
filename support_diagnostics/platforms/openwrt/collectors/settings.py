import collections
import json
import os

from support_diagnostics import Collector,CollectorResult

class SettingsCollector(Collector):
    id = "settings"

    settings_file_name = "/etc/config/settings.json"

    """
    Get MFW settings
    """
    def collect(self):
        results = []

        result = CollectorResult(self, SettingsCollector.id)
        if os.path.isfile(SettingsCollector.settings_file_name):
            with open(SettingsCollector.settings_file_name, "r") as file:
                result.output = json.load(file,object_pairs_hook=collections.OrderedDict)
                
        results.append(result)

        return results