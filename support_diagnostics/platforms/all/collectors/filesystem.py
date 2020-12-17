import re
import subprocess
from os.path import dirname, basename, isfile, join

from support_diagnostics import Collector,CollectorResult
import support_diagnostics

## !!! move to utils
def human_to_byte(size):
    """
    Convert a human readable value like 20G to 21474836480
    """
    result = 0
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    match = re.search('([\d+\.]+)\s*(.+)', size)
    if match is not None:
        number = float(match.group(1))
        unit = match.group(2).upper()
        if not unit.endswith('B'):
            unit = unit + 'B'
        if unit in size_name:
            factor = 1024 ** size_name.index(unit)
            result = number * factor
    return int(result)

class FilesystemCollector(Collector):

    platform_entries = {
        'openwrt': [ '/tmp/reports.db'],
        'debian': [ '/var/log', '/var/lib/postgresql', '/etc', '/usr/share/untangle' ]
    }

    """
    Get NGFW system information
    """
    def collect(self):
        results = []

        # Partition usage
        result = CollectorResult(self, "partition")

        proc = subprocess.Popen(['fdisk', '-l'], stdout=subprocess.PIPE)
        partitions = {
            '/tmp': {
                'type': 'tmpfs',
                'boot': False,
                'start': None,
                'end': None
            }
        }
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.decode("ascii").rstrip()
            if line.startswith('/'):
                boot = False
                if '*' in line:
                    boot = True
                # Remove the boot partition indicato
                line = line.replace('*','')
                fields = re.split(r'\s+',line)
                if len(fields) > 5:
                    partitions[fields[0]] = {
                        'size': human_to_byte(fields[4]),
                        'start': fields[1],
                        'end': fields[2],
                        'id': fields[5],
                        'type': fields[6],
                        'boot': boot,
                        'match': None
                    }

        proc = subprocess.Popen(['df'], stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.decode("ascii").rstrip()
            fields = re.split(r'\s+',line)
            if len(fields) > 5:
                # print(fields)
                mount_point = fields[0]
                if mount_point == 'tmpfs':
                    if fields[5] not in ['/tmp', '/dev/shm']:
                        continue
                    mount_point = "/tmp"
                if mount_point in partitions:
                    partitions[mount_point]['match'] = 'df'
                    partitions[mount_point]['used'] = int(fields[2]) * 1024
                    partitions[mount_point]['available'] = int(fields[3]) * 1024
                    partitions[mount_point]['mount'] = fields[5]
                    if 'size' not in partitions[mount_point]:
                        partitions[mount_point]['size'] = int(fields[1]) * 1024

        proc = subprocess.Popen(['swapon', "-s"], stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.decode("ascii").rstrip()
            fields = re.split(r'\s+',line)
            if len(fields) > 3:
                mount_point = fields[0]
                if mount_point in partitions:
                    partitions[mount_point]['match'] = 'swapon'
                    partitions[mount_point]['type'] = 'swap'

        deletes = []
        for partition in partitions:
            if partitions[partition]['match'] is None:
                for partition_delete in partitions:
                    if partition != partition_delete:
                        if partitions[partition_delete]['end'] is not None and partitions[partition]['end'] is not None:
                            if partitions[partition_delete]['end'] == partitions[partition]['end']:
                                if partition_delete not in deletes:
                                    deletes.append(partition)

        for delete in deletes:
            del partitions[delete]

        result.output = partitions
        results.append(result)

        # Entry usage
        result = CollectorResult(self, "entries")
        entries = {}
        platform = support_diagnostics.Configuration.platform
        if platform in self.platform_entries:
            for entry in self.platform_entries[support_diagnostics.Configuration.platform]:
                # openwrt does not have -b option.
                proc = subprocess.Popen(['du', "-s", entry], stdout=subprocess.PIPE)
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    line = line.decode("ascii").rstrip()
                    fields = re.split(r'\s+',line)
                    # convert to bytes
                    entries[entry] = int(fields[0]) * 1024

        result.output = entries
        results.append(result)

        return results