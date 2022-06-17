import glob
import gzip
from os.path import dirname, basename, isfile, join
import re
import subprocess

from datetime import datetime
import time

from support_diagnostics import Collector,CollectorResult

class IpsecStatusAllCollector(Collector):
    """
    Parse ipsec statusall results
    """
    id = "ipsec_statusall"

    def __init__(self, id=None, path=None, ignore=None):
        if id is not None:
            self.id = id

    sections = {
        "Status": "status",
        "Listening IP addresses:" : "listeners",
        # There is a separate Security Associations section too, but we just combine the two together
        "Connections:": "connections"
    }

    status_uptime_re = re.compile('uptime: .* since (.+)$')
    status_worker_re = re.compile('worker threads: ([^\s]+) of ([^\s]+) idle, ([^\s]+) working, job queue: ([^\s]+), scheduled: ([^\s]+)$')
    status_loaded_plugins_re = re.compile('loaded plugins: (.+)$')

    connection_id_re = re.compile('([^\[]+)_(\d)+(|[(\d+)])')

    connection_gw_re = re.compile('(local|remote):\s+\[([^\]]+)\] uses (.*)')
    connection_tunnel_re = re.compile('child:\s+([^\s]+) === ([^\s]+) ([^\s]+),')
    connection_established_re = re.compile('ESTABLISHED ([^\s]+) ([^\s]+) ago,')
    connection_ike_spis_re = re.compile('IKEv(\d+) SPIs: ([^,]+), .* reauthentication in ([^\s]+)\s+([^\s]+)')
    connection_ike_proposal_re = re.compile('IKE proposal: ([^\/]+)/([^\/]+)/([^\/]+)')

    connection_esp_spis_re = re.compile('reqid ([^\s]+), ESP SPIs: (.+)')
    # There's the possibility of some mix where one we saw traffic in but no traffic out or visa versa.  That's not accounted for here.
    connection_esp_proposal_no_traffic_re = re.compile('([^\s]+), (\d+) bytes_i, (\d+) bytes_o, rekeying in ([^\s]+) ([^\s]+)')
    connection_esp_proposal_traffic_re = re.compile('([^\s]+), (\d+) bytes_i \(([^\s]+) pkts, ([^\s]+) ago\), (\d+) bytes_o \(([^\s]+) pkts, ([^\s]+) ago\), rekeying in ([^\s]+) ([^\s]+)')
    
    def collect(self):
        """
        Build statusall entries
        """
        results = []
        proc = subprocess.Popen(['ipsec', 'statusall'], stdout=subprocess.PIPE)

        result = None
        section = None
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.decode("ascii").rstrip()

            current_section = section
            for key in IpsecStatusAllCollector.sections:
                if line.startswith(key):
                    if not result is None:
                        results.append(result)
                    section = IpsecStatusAllCollector.sections[key]
                    # result.output[section] = {}
                    result = CollectorResult(self, section)
                    result.output = {}
                    break

            if current_section != section:
                # Ignore headers
                continue
    
            if section == "status":
                matches = IpsecStatusAllCollector.status_uptime_re.search(line)
                if not matches is None:
                    d = datetime.strptime(matches.group(1), "%b  %d %H:%M:%S %Y")
                    timestamp = int(time.mktime(d.timetuple()))
                    result.output["uptime"] = timestamp
                    continue
                matches = IpsecStatusAllCollector.status_worker_re.search(line)
                if not matches is None:
                    result.output["workers"] = {
                        "idle": int(matches.group(1)),
                        "max_idle": int(matches.group(2)),
                        "working": matches.group(3),
                        "queue": matches.group(4),
                        "scheduled": int(matches.group(5)),
                    }
                    continue
                matches = IpsecStatusAllCollector.status_loaded_plugins_re.search(line)
                if not matches is None:
                    result.output["plugins"] = matches.group(1).split(" ")
                    continue
            elif section == "listeners":
                if not "addresses" in result.output:
                    result.output["addresses"] = []
                result.output["addresses"].append(line.strip())
                continue
            elif section == "connections":
                items = line.split(":", 1)
                matches = IpsecStatusAllCollector.connection_id_re.search(items[0])
                id = None
                tunnel_index = None
                if not matches is None:
                    id = matches.group(1)
                    tunnel_index = int(matches.group(2)) -1
                if id not in result.output:
                    result.output[id] = {
                        "ike": {}
                    }

                if len(items) < 2:
                    continue

                matches = IpsecStatusAllCollector.connection_gw_re.search(items[1])
                if not matches is None:
                    sub_id = matches.group(1)
                    result.output[id][sub_id] = {
                        "gateway": matches.group(2),
                        "auth": matches.group(3)
                    }
                    continue

                matches = IpsecStatusAllCollector.connection_tunnel_re.search(items[1])
                if not matches is None:
                    sub_id = "tunnels"
                    if sub_id not in result.output[id]:
                        result.output[id][sub_id] = []
                    network = {
                        "local": matches.group(1),
                        "remote": matches.group(2),
                        "type": matches.group(3)
                    }
                    result.output[id][sub_id].append(network)
                    continue

                matches = IpsecStatusAllCollector.connection_established_re.search(items[1])
                if not matches is None:
                    result.output[id]["ike"]["established_s"] = self.get_seconds(matches.group(1), matches.group(2))
                    continue

                matches = IpsecStatusAllCollector.connection_ike_spis_re.search(items[1])
                if not matches is None:
                    result.output[id]["ike"]["version"] = int(matches.group(1))
                    result.output[id]["ike"]["spis"] = matches.group(2).strip().split()
                    result.output[id]["ike"]["next_s"] = self.get_seconds(matches.group(3), matches.group(4))
                    continue

                matches = IpsecStatusAllCollector.connection_ike_proposal_re.search(items[1])
                if not matches is None:
                    result.output[id]["ike"]["proposal"] = {
                        "encryption": matches.group(1),
                        "algorithm": matches.group(2),
                        "group": matches.group(3),
                    }
                    continue

                matches = IpsecStatusAllCollector.connection_esp_spis_re.search(items[1])
                if not matches is None:
                    result.output[id]["tunnels"][tunnel_index]["reqid"] = int(matches.group(1))
                    result.output[id]["tunnels"][tunnel_index]["spis"] = matches.group(2).strip().split()
                    continue

                matches = IpsecStatusAllCollector.connection_esp_proposal_no_traffic_re.search(items[1])
                if not matches is None:
                    result.output[id]["tunnels"][tunnel_index]["proposal"] = matches.group(1)
                    result.output[id]["tunnels"][tunnel_index]["traffic"] = {
                        "in": {
                            "bytes": matches.group(2),
                            "packets": 0,
                            "last_s": 0
                        },
                        "out": {
                            "bytes": matches.group(3),
                            "packets": 0,
                            "last_s": 0
                        }
                    }
                    result.output[id]["tunnels"][tunnel_index]["rekey_s"] = self.get_seconds(matches.group(4), matches.group(5))
                    continue

                matches = IpsecStatusAllCollector.connection_esp_proposal_traffic_re.search(items[1])
                if not matches is None:
                    result.output[id]["tunnels"][tunnel_index]["proposal"] = matches.group(1)
                    result.output[id]["tunnels"][tunnel_index]["traffic"] = {
                        "in": {
                            "bytes": matches.group(2),
                            "packets": matches.group(3),
                            "last_s": int(matches.group(4)[:-1])
                        },
                        "out": {
                            "bytes": matches.group(5),
                            "packets": matches.group(6),
                            "last_s": int(matches.group(7)[:-1])
                        }
                    }
                    result.output[id]["tunnels"][tunnel_index]["rekey_s"] = self.get_seconds(matches.group(8), matches.group(9))
                    continue

        if not result is None:
            results.append(result)
        return results

    def get_seconds(self, value, units):
        seconds = int(value)
        if units == "hours":
            seconds *= 3600
        elif units == "minutes":
            seconds *= 60
        return seconds