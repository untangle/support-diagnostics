from os.path import dirname, basename, isfile, join
import re
import subprocess

from support_diagnostics import Collector,CollectorResult

class IpTunnelCollector(Collector):
    """
    Get ip tunnel entries
    """
    id = "ip_tunnel"

    def __init__(self, id=None, path=None, ignore=None):
        if id is not None:
            self.id = id

    header_keys = [ "ttl", "ikey", "okey", "key"]
    header_re = re.compile('([^:]+): ip/ip remote ([^\s]+) local ([^\s]+) (.*)$')

    def collect(self):
        """
        Collect tunnel information into single entries for each tunnel.
        """
        results = []
        proc = subprocess.Popen(['ip', '-s','tunnel'], stdout=subprocess.PIPE)

        result = None
        in_header = False
        stat_key = None
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.decode("ascii").rstrip()

            matches = IpTunnelCollector.header_re.search(line)
            if not matches is None:
                if not result is None:
                    results.append(result)

                in_header = True
                result = CollectorResult(self, "ip_xfrm_state")
                result.output= {
                    "interface": matches.group(1),
                    "remote": matches.group(2),
                    "local": matches.group(3),
                    "raw": [line]
                }
                # Space separated key/value pairs
                other_fields = matches.group(4).split(" ")
                was_key_pair = False
                for index, key in enumerate(other_fields):
                    if was_key_pair is True:
                        was_key_pair = False
                        continue
                    if key in IpTunnelCollector.header_keys:
                        result.output[key] = other_fields[index + 1]
                        was_key_pair = True
                    else:
                        result.output[key] = True
            else:
                if not in_header is True:
                    continue
                result.output["raw"].append(line)

                if stat_key is not None:
                    other_fields = line.strip().split()
                    result.output[stat_key] = {
                        "packets": other_fields[0],
                        "bytes": other_fields[1],
                        "errors": other_fields[2],
                        "dead_loop": other_fields[3],
                        "no_route": other_fields[4],
                        "no_bufs": other_fields[5],
                    }
                    stat_key = None
                    continue

                if line.startswith("RX:"):
                    stat_key = "rx"
                elif line.startswith("TX:"):
                    stat_key = "tx"
                else:
                    stat_key = None

                if stat_key is not None:
                    continue
                    
        if not result is None:
            results.append(result)
        return results
