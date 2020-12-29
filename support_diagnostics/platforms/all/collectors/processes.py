import re
import glob
import subprocess
from os.path import dirname, basename, isfile, join
import os

from support_diagnostics import Collector,CollectorResult
import support_diagnostics.utilities
import support_diagnostics

class ProcessesCollector(Collector):
    """
    Collect memmory from running processes
    """
    process_id_re = re.compile('.*\/(\d+)$')

    process_cmdline_name = "/proc/{process_id}/cmdline"
    process_status_name = "/proc/{process_id}/status"
    
    def collect(self):
        results = []
        for process_id in glob.glob("/proc/*"):
            matches = ProcessesCollector.process_id_re.search(process_id)
            if matches is None:
                continue
            process_id = matches.group(1)

            result = CollectorResult(self, 'process')
            file = open(ProcessesCollector.process_status_name.format(process_id=process_id), "r")
            status = {}
            for line in file.readlines():
                fields = line.strip().split(':')
                key = fields[0].strip().lower()
                value = ':'.join(fields[1:]).strip()
                if support_diagnostics.utilities.SizeConversion.is_human(value):
                    value = support_diagnostics.utilities.SizeConversion.from_human(value)
                status[key] = value
            file.close()

            file = open(ProcessesCollector.process_cmdline_name.format(process_id=process_id), "r")
            cmdline = open(ProcessesCollector.process_cmdline_name.format(process_id=process_id), "rb").read().replace(b'\0',b' ').decode()

            process_result = {
                'id': process_id,
                'cmdline': cmdline,
                'status': status
            }

            result.output = process_result
            results.append(result)

        return results