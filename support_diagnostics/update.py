import os
#import requests
import shutil
import subprocess
import sys
import tarfile
import time

from support_diagnostics import Configuration

class Update():
    checked = False
    chunk_size = 1024 * 1024
    check_interval = 86400
    # url = "https://download.untangle.com/support_diagnostics.tgz"
    url = "http://192.168.25.51/support_diagnostics.tgz"
    download_file_path = "support_diagnostics.tgz"

    @classmethod
    def check(cls):
        Update.download_file_path = "{home_path}/{file_name}".format(home_path=Configuration.user_path, file_name=Update.download_file_path)
        current_time = int(time.time())
        last_check_time = Configuration.get_settings()['updates']['last_check_time']
        if last_check_time == 0 or (last_check_time + Update.check_interval) < current_time:
            print("Checking for update")
            if Update.download() is True and Update.install():
                Configuration.get_settings()['updates']['last_check_time'] = current_time
                Configuration.write()
                print("Updated - re-run command")
                sys.exit(1)
        
    @classmethod
    def download(cls):
        """
        Download tarball.
        """
        request = None
        try:
            request = requests.get(Update.url, timeout=5)
        except:
            print(":".join([cls.__name__, sys._getframe().f_code.co_name, "Cannot open {url}".format(url=Update.url)]))
            return False

        if request.status_code == 404:
            print(":".join([cls.__name__, sys._getframe().f_code.co_name, "server returned 404 for {url}".format(url=Update.url)]))
            return False

        url_file_size = int(request.headers['content-length'])
        if url_file_size == 0:
            print(":".join([cls.__name__, sys._getframe().f_code.co_name, "content length for {url} is 0".format(url=Update.url)]))
            return False

        last_content_length = Configuration.get_settings()['updates']['last_content_length']

        if last_content_length == url_file_size:
            # if self.debug:
                # print(":".join([cls.__name__, sys._getframe().f_code.co_name, "current and url sies are the same {size}".format(size=url_file_size)]))
            return False

        try:
            url = requests.get(Update.url)
        except:
            print(":".join([cls.__name__, sys._getframe().f_code.co_name, "can't open url {url}".format(url=url)]))
            return False

        try:
            write_file = open(Update.download_file_path, 'wb')
        except:
            print(":".join([cls.__name__, sys._getframe().f_code.co_name, "Cannot create local file {file_path}".format(file_path=Update.download_file_path)]))
            return False

        try:
            for chunk in url.iter_content(chunk_size=Update.chunk_size):
                if chunk:
                    write_file.write(chunk)
        except:
            print(":".join([cls.__name__, sys._getframe().f_code.co_name, "Cannot write to {file_path}".format(file_path=Update.download_file_path)]))
            return False

        write_file.close()

        settings = Configuration.get_settings()['updates']['last_content_length'] = url_file_size
        return True

    @classmethod
    def install(cls):
        untar_target_path = "{home_path}/{file_name}".format(home_path=Configuration.user_path, file_name="support_diagnostics")
        if os.path.isdir(untar_target_path):
            shutil.rmtree(untar_target_path)

        try:
            tar = tarfile.open(Update.download_file_path)
            tar.extractall(path=untar_target_path)
            tar.close()
        except:
            print(":".join([cls.__name__, sys._getframe().f_code.co_name, "Cannot extract to {file_path}".format(file_path=untar_target_path)]))
            sys.exit(1)

        try:
            command = "{path}/{directory}/{command}".format(path=untar_target_path,directory="support_diagnostics",command="install.sh")
            proc = subprocess.Popen([command])
        except:
            print(":".join([cls.__name__, sys._getframe().f_code.co_name, "Cannot run command {command}".format(command=command)]))
            sys.exit(1)

        return True

