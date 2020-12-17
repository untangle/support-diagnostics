import copy
import re

# from urllib.parse import urlparse
import urllib.parse

from support_diagnostics import Analyzer, AnalyzerResult, AnalyzerResultSeverityPass, AnalyzerResultSeverityWarn, AnalyzerResultSeverityFail
from support_diagnostics import Configuration, ImportModules

ImportModules.import_all(globals(), "collectors")

## !!! library
def byte_to_human(size, decimal_places=2):
    for unit in [ 'B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if size < 1024.0 or unit == 'PB':
            break
        size /= 1024.0
    return f"{size:.{decimal_places}f} {unit}"

class PartitionsAnalyzer(Analyzer):
    """
    Get apt sources
    """
    order = 0
    
    heading = "Partition Usage"
    categories = ["os"]
    collector = FilesystemCollector

    results = {
        "critical": AnalyzerResult(
                severity=AnalyzerResultSeverityFail,
                summary='Disk usage critical',
                detail=None,
                recommendation=None,
                other_results={
                    '{severity}': '{type:<10} {partition:<15}-> {mount:<10} {percent_used:<10} {summary}'
                }
        ),
        "near-critical": AnalyzerResult(
                severity=AnalyzerResultSeverityWarn,
                summary='Disk usage near critical',
                detail=None,
                recommendation=None,
                other_results={
                    '{severity}': '{type:<10} {partition:<15}-> {mount:<10} {percent_used} {summary}'
                }
        ),
        "non-critical": AnalyzerResult(
                severity=AnalyzerResultSeverityPass,
                summary='',
                detail=None,
                recommendation=None,
                other_results={
                    '{severity}': '{type:<10} {partition:<15}-> {mount:<10} {percent_used} {summary}'
                }
        ),
    }

    def analyze(self, collector_results):
        results = []
        result_fields = {}
        format_fields = {}
        severity=None
        for collector_result in collector_results:
            if collector_result.source == "partition":
                for partition in collector_result.output:
                    format_fields = {
                        'partition': partition,
                        'mount': 'unknown',
                        'percent_used': 'unknown',
                        'type': 'unknown',
                    }
                    percent_used = None
                    # print(collector_result.output[partition])
                    if 'used' in collector_result.output[partition] and collector_result.output[partition]['size'] > 0:
                        percent_used = int(round(collector_result.output[partition]['used'] / collector_result.output[partition]['size'] * 100, 0))
                        format_fields['percent_used'] = '{percent_used}%'.format(percent_used=percent_used)

                    if 'mount' in collector_result.output[partition]:
                        format_fields['mount'] = collector_result.output[partition]['mount']
                    if 'type' in collector_result.output[partition]:
                        format_fields['type'] = collector_result.output[partition]['type']
                
                    if collector_result.output[partition]['type'] == 'swap':
                        result = copy.deepcopy(PartitionsAnalyzer.results['non-critical'])
                        format_fields['percent_used'] = '-'
                        format_fields['mount'] = '-'
                    elif percent_used is None:
                        result = copy.deepcopy(PartitionsAnalyzer.results['near-critical'])
                        result.results['summary'] = ''
                    elif percent_used >= 95:
                        result = copy.deepcopy(PartitionsAnalyzer.results['critical'])
                    # elif percent_used > 80 or percent_used is None:
                    elif percent_used >= 85 or percent_used is None:
                        result = copy.deepcopy(PartitionsAnalyzer.results['near-critical'])
                    else:
                        result = copy.deepcopy(PartitionsAnalyzer.results['non-critical'])

                    result.collector_result = collector_result
                    result.analyzer = self
                    result.format(format_fields)
                    results.append(result)

        return results