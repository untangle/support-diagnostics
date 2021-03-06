import os
import urllib.request
import shutil
import subprocess
import sys
import tarfile
import time

from support_diagnostics import Configuration, Logger

class Update():
    checked = False
    chunk_size = 1024 * 1024
    check_interval = 86400
    url = "https://updates.untangle.com/support_diagnostics.tgz"
    download_file_path = "support_diagnostics.tgz"

    @classmethod
    def check(cls):
        Update.download_file_path = "{home_path}/{file_name}".format(home_path=Configuration.user_path, file_name=Update.download_file_path)
        current_time = int(time.time())
        last_check_time = Configuration.get_settings()['updates']['last_check_time']
        if last_check_time == 0 or (last_check_time + Update.check_interval) < current_time:
            Configuration.get_settings()['updates']['last_check_time'] = current_time
            Configuration.write()
            if Update.download() is True and Update.install():
                print("Updated - re-run command")
                sys.exit(1)
            print()
        
    @classmethod
    def download(cls):
        """
        Download tarball.
        """
        print("Checking for updates...", end='', flush=True)
        response = None
        try:
            request = urllib.request.Request(Update.url, method="HEAD")
            response = urllib.request.urlopen(request)
        except:
            Logger.message(f"Cannot open {Update.url}")
            return False

        if response.status == 404:
            Logger.message(f"server returned 404 for {Update.url}")
            return False

        url_file_size = int(response.getheader("Content-length"))
        if url_file_size == 0:
            Logger.message(f"content length for {Update.url} is 0")
            return False

        last_content_length = Configuration.get_settings()['updates']['last_content_length']

        if last_content_length == url_file_size:
            # if self.debug:
                # Logger.message(f"current and url sies are the same {url_file_size}")
            return False

        print("downloading...", end='', flush=True)
        try:
            url = urllib.request.urlopen(Update.url, timeout=5)
        except:
            Logger.message(f"can't open url {Update.url}")
            return False

        try:
            write_file = open(Update.download_file_path, 'wb')
        except:
            Logger.message(f"Cannot create local file {Update.download_file_path}")
            return False

        url_bytes_read = 0
        while url_bytes_read < url_file_size:
            print(".", end='', flush=True)
            try:
                data = url.read(Update.chunk_size)
            except:
                Logger.message(f"Cannot read content at {url_bytes_read}")
                return False

            url_bytes_read += len(data)

            try:
                write_file.write(data)
            except:
                Logger.message(f"Cannot write content at {url_bytes_read}")
                return False

        write_file.close()

        settings = Configuration.get_settings()['updates']['last_content_length'] = url_file_size
        return True

    @classmethod
    def install(cls):
        print("installing...", end='', flush=True)
        untar_target_path = "{home_path}/{file_name}".format(home_path=Configuration.user_path, file_name="support_diagnostics")
        if os.path.isdir(untar_target_path):
            shutil.rmtree(untar_target_path)

        try:
            tar = tarfile.open(Update.download_file_path)
            tar.extractall(path=untar_target_path)
            tar.close()
        except:
            Logger.message(f"Cannot extract to {untar_target_path}")
            sys.exit(1)

        try:
            command = "{path}/{directory}/{command}".format(path=untar_target_path,directory="support_diagnostics",command="install.sh")
            proc = subprocess.Popen([command])
        except:
            Logger.message(f"Cannot run command {command}")
            sys.exit(1)

        return True

