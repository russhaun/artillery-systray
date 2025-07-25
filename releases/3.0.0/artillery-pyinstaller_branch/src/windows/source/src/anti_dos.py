#!/usr/bin/python
#
# basic for now, more to come
#
import subprocess
from src.core import write_console
from src.config import anti_dos_ports, anti_dos_burst_limit, anti_dos_throttle_connections, is_posix_os


def start_anti_dos():
    if is_posix_os is True:
        write_console("[*] Activating anti DoS.")
        anti_dos_ports_split = anti_dos_ports.split(",")
        for ports in anti_dos_ports_split:
            subprocess.Popen("iptables -A ARTILLERY -p tcp --dport %s -m limit --limit %s/minute --limit-burst %s -j ACCEPT" %
                (ports, anti_dos_throttle_connections, anti_dos_burst_limit), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
    else:
        return
#
