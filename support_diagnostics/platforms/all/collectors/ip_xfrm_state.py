import glob
import gzip
from os.path import dirname, basename, isfile, join
import re
import subprocess

from support_diagnostics import Collector,CollectorResult

class IpXfrmStateCollector(Collector):
    """
    Parse ip xfrm state information
    """
    id = "ip_xfrm_state"

    def __init__(self, id=None, path=None, ignore=None):
        if id is not None:
            self.id = id

    header_re = re.compile('src ([^\s]+) dst ([^\s]+)$')
    proto_re = re.compile('\s+proto ([^\s]+) spi ([^\s]+) reqid ([^\s]+) mode ([^\s]+)$')
    replay_re = re.compile('\s+replay-window ([^\s]+) flag ([^\s]+)$')
    mark_re = re.compile('\s+mark ([^\s]+)/([^\s]+)$')
    aead_re = re.compile('\s+aead ([^\s]+) ([^\s]+) ([^\s]+)$')
    anti_replay_re = re.compile('\s+anti-replay context: seq ([^,]+), oseq ([^,]+), bitmap ([^\s]+)$')

    def collect(self):
        """
        Build policy entries
        """
        results = []
        proc = subprocess.Popen(['ip', 'xfrm','state'], stdout=subprocess.PIPE)

        result = None
        in_header = False
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.decode("ascii").rstrip()

            matches = IpXfrmStateCollector.header_re.search(line)
            if not matches is None:
                if not result is None:
                    results.append(result)

                in_header = True
                result = CollectorResult(self, IpXfrmStateCollector.id)
                result.output= {
                    "src": matches.group(1),
                    "dst": matches.group(2),
                    "raw": [line]
                }
            else:
                if not in_header is True:
                    continue
                result.output["raw"].append(line)
                matches = IpXfrmStateCollector.proto_re.search(line)
                if not matches is None:
                    result.output["proto"] = matches.group(1)
                    result.output["spi"] = matches.group(2)
                    result.output["reqid"] = matches.group(3)
                    result.output["mode"] = matches.group(4)
                    continue
                
                matches = IpXfrmStateCollector.replay_re.search(line)
                if not matches is None:
                    result.output["replay-window"] = matches.group(1)
                    result.output["flag"] = matches.group(2)
                    continue

                matches = IpXfrmStateCollector.mark_re.search(line)
                if not matches is None:
                    result.output["mark"] = {
                        "mark": matches.group(1),
                        "mark_integer": int(matches.group(1).strip("0")[1:],16),
                        "mask": matches.group(2)
                    }

                matches = IpXfrmStateCollector.aead_re.search(line)
                if not matches is None:
                    result.output["aead"] = {
                        "cipher": matches.group(1),
                        "id": matches.group(2)
                    }
                    continue

                matches = IpXfrmStateCollector.anti_replay_re.search(line)
                if not matches is None:
                    result.output["anti-replay-context"] = {
                        "seq": matches.group(1),
                        "oseq": matches.group(2),
                        "bitmap": matches.group(3)
                    }
                    continue
                
                if "unknown" not in result.output:
                    result.output["unknown"] = []
                result.output["unknown"].append(line.strip())

        if not result is None:
            results.append(result)
        return results
