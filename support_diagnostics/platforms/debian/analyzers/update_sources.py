import copy
import re

# from urllib.parse import urlparse
import urllib.parse

from support_diagnostics import Analyzer, AnalyzerResult, AnalyzerResultSeverityPass, AnalyzerResultSeverityWarn, AnalyzerResultSeverityFail
from support_diagnostics import Configuration, ImportModules

ImportModules.import_all(globals(), "collectors")

class UpdateSourceAnalyzer(Analyzer):
    """
    Get apt sources
    """
    categories = ["updates"]
    collector = AptSourcesCollector

    deb_re = re.compile('^(?P<type>deb[^\s]*)\s+(\[.+\]\s+|)(?P<url>[^\s+]+)\s+(?P<distribution>[^\s+]+)(.*)')

    heading = "Debian apt sources"
    results = {
        "public": AnalyzerResult(
                severity=AnalyzerResultSeverityPass,
                summary="Pointing to production package server '{host}'",
                detail="All customer units should be using this package server."
        ),
        "internal": AnalyzerResult(
                severity=AnalyzerResultSeverityWarn,
                summary="Pointing to development package server '{host}'",
                detail="For internal Untangle corporate units this is acceptable, but not for customer units.",
                recommendation="If this is a customer facing system, change the host to updates.untangle.com"
        ),
        "unknown": AnalyzerResult(
                severity=AnalyzerResultSeverityFail,
                summary="Pointing to unknown server '{host}'",
                detail="No customer or corporate units should be pointing to an unknown package server",
                recommendation="From file:\n\t\t{collector_result_source}:\n\t\tdelete entry:\n\t\t{entry}"
        )
    }

    def analyze(self, collector_results):
        results = []
        for collector_result in collector_results:
            for line in collector_result.output:
                if line.startswith('#') or len(line) == 0:
                    # Ignore comments, blank lines.
                    continue
                match = self.deb_re.search(line)
                if match is not None:
                    url = match.group("url")
                    # parsed_url = urlparse(url)
                    parsed_url = urllib.parse.urlsplit(url)

                    result = None
                    if parsed_url.hostname == 'updates.untangle.com':
                        result = copy.deepcopy(UpdateSourceAnalyzer.results["public"])
                    elif parsed_url.hostname == 'package-server.untangle.int':
                        result = copy.deepcopy(UpdateSourceAnalyzer.results["internal"])
                    else:
                        result = copy.deepcopy(UpdateSourceAnalyzer.results["unknown"])
                    
                    result.collector_result = collector_result
                    result.analyzer = self
                    result.format({
                        "entry": line,
                        "host": parsed_url.hostname
                    })
                    results.append(result)
        return results