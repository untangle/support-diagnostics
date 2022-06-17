# import collections
import glob
import gzip
from os.path import dirname, basename, isfile, join
import re
import subprocess

from support_diagnostics import Collector,CollectorResult

class IpXfrmPolicyCollector(Collector):
    """
    Parse ip xfrm policy
    """
    id = "ip_xfrm_policy"
    header_re = re.compile('^src ([^\s]+) dst ([^\s]+)$')
    dir_re = re.compile('(socket|dir) ([^\s]+) priority ([^\s]+)$')
    mark_re = re.compile('mark ([^\/]+)/([^\s]+)$')
    tmpl_re = re.compile('tmpl src ([^\s]+) dst ([^\s]+)$')
    proto_re = re.compile('proto ([^\s]+) (.*)$')

    def __init__(self, id=None, path=None, ignore=None):
        if id is not None:
            self.id = id

    def collect(self):
        """
        Build policy entries
        """
        results = []
        proc = subprocess.Popen(['ip', 'xfrm', 'policy'], stdout=subprocess.PIPE)

        result = None
        in_header = False
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.decode("ascii").rstrip()

            matches = IpXfrmPolicyCollector.header_re.search(line)
            if not matches is None:
                if not result is None:
                    results.append(result)

                in_header = True
                result = CollectorResult(self, IpXfrmPolicyCollector.id)
                result.output= {
                    "src": matches.group(1),
                    "dst": matches.group(2),
                    "raw": [line]
                }
            else:
                if not in_header is True:
                    continue
                result.output["raw"].append(line)
                matches = IpXfrmPolicyCollector.dir_re.search(line)
                if not matches is None:
                    result.output["type"] = matches.group(1)
                    result.output["direction"] = matches.group(2)
                    result.output["priority"] = int(matches.group(3))
                    continue
                matches = IpXfrmPolicyCollector.mark_re.search(line)
                if not matches is None:
                    result.output["mark"] = {
                        "mark": matches.group(1),
                        "mark_integer": int(matches.group(1).strip("0")[1:],16),
                        "mark_mask": matches.group(2)
                    }
                    continue
                matches = IpXfrmPolicyCollector.tmpl_re.search(line)
                if not matches is None:
                    result.output["tunnel"] = {
                        "src": matches.group(1),
                        "dst": matches.group(2)
                    }
                    continue
                matches = IpXfrmPolicyCollector.proto_re.search(line)
                if not matches is None:
                    result.output["proto"] = {
                        "proto": matches.group(1)
                    }
                    # Space separated key/value pairs
                    other_fields = matches.group(2).split(" ")
                    for index, key in enumerate(other_fields):
                        if index %2 != 0:
                            continue
                        result.output["proto"][key] = other_fields[index + 1]
                    continue

        if not result is None:
            results.append(result)
        return results
