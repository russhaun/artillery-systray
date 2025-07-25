# 127.0.0.1 - - [10/Mar/2012:15:35:53 -0500] "GET /sdfsdfds.dsfds
# HTTP/1.1" 404 501 "-" "Mozilla/5.0 (X11; Linux i686 on x86_64;
# rv:10.0.2) Gecko/20100101 Firefox/10.0.2"
from src.config import access_log_path, error_log_path, is_posix_os


def tail(some_file):
    this_file = open(some_file)
    # Go to the end of the file
    this_file.seek(0, 2)

    while True:
        line = this_file.readline()
        if line:
            yield line
        yield None


def start_apache_log_monitor():
    """
    Monitors Access and Error logs on apache servers
    """
    if is_posix_os is True:
        tail(access_log_path)
        tail(error_log_path)
    else:
        return
