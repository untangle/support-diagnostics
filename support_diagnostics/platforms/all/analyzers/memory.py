import copy
import os
import re

# from urllib.parse import urlparse
import urllib.parse

from support_diagnostics import Analyzer, AnalyzerResult, AnalyzerResultSeverityPass, AnalyzerResultSeverityWarn, AnalyzerResultSeverityFail
from support_diagnostics import Configuration, ImportModules
import support_diagnostics.utilities

ImportModules.import_all(globals(), "collectors")

class MemoryAnalyzer(Analyzer):
    """
    Analyze memory usage
    """
    order = 0
    
    heading = "Process Memory Usage"
    categories = ["os"]
    collector = ProcessesCollector

    def analyze(self, collector_results):
        results = []

        memory_sorted_process_results = sorted(filter(lambda r: r.source == "process" and 'vmrss' in r.output['status'], collector_results), key=lambda d: d.output['status']['vmrss'], reverse=True)
        for process_result in memory_sorted_process_results[:10]:
            result = AnalyzerResult(severity=AnalyzerResultSeverityPass,other_results={ "{severity}" : '{cmdline:<55} {size}'})
            cmdline_len = len(process_result.output['cmdline'])
            format_fields = {
                'cmdline': '{process}{elide}'.format(process=process_result.output['cmdline'][:50], elide='...' if cmdline_len > 50 else ''),
                'size': support_diagnostics.utilities.SizeConversion.to_human(process_result.output['status']['vmrss'])
            }
            result.collector_result = process_result
            result.analyzer = self
            result.format(format_fields)
            results.append(result)

        return results