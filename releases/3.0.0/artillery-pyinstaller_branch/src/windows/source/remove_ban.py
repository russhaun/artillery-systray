##!/usr/bin/python
#
# simple remove banned ip
#
#
import re
import sys
import subprocess
from src.config import is_windows_os, is_posix_os
from src.core import is_valid_ipv4, write_console, globals, check_banlist_path
if is_windows_os is True:
    from src.pyuac import isUserAdmin
    #


def linux_route():
    """
    removes given ip addr from iptables and also banlist
    """
    try:
        ipaddress = sys.argv[1]
        #read banlist path
        path = check_banlist_path()
        if is_valid_ipv4(ipaddress):
            write_console(f"Searching iptables chain looking for {ipaddress}... If there is a massive amount of blocked IP's this could take a few minutes..")
            proc = subprocess.Popen("iptables -L ARTILLERY -n -v --line-numbers | grep %s" % (
                ipaddress), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            #
            for line in proc.stdout.readlines():
                line = str(line)
                match = re.search(ipaddress, line)
                if match:
                    line = line.split(" ")
                    #this is the rule number
                    line = line[0]
                    write_console(f"Deleting entry {line} from iptables chain")
                    # delete entry from iptables chain
                    subprocess.Popen("iptables -D ARTILLERY %s" % (line), stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
                    #remove entry from banlist
                    fileopen = open(path, "r")
                    data = fileopen.read()
                    data = data.replace(ipaddress + "\n", "")
                    filewrite = open(path, "w")
                    filewrite.write(data)
                    filewrite.close()
        # if not valid then flag
        else:
            write_console("[!] Not a valid IP Address. Exiting.")
            sys.exit()
    except IndexError:
        write_console("Description: Simple removal of IP address from banned sites.")
        write_console("[!] Usage: remove_ban.py <ip_address_to_ban>")


def windows_route():

    """
    this will attempt to delete given ip from windows routing table using built in commands
    """
    if not isUserAdmin():
        write_console("[!] This script requires admin. Please relaunch from an elevated command prompt.")
        pause = input("[*] Press any key to continue")
        sys.exit()
    if isUserAdmin():
        def delete_route(ip):
            try:
                write_console("[*] Trying to delete entry.....")
                cmd = subprocess.run(['cmd', '/C', 'route', 'delete', ip], shell=True, check=True)
            except subprocess.CalledProcessError as err:
                write_console("[*] " + err)
        #
        try:
            ipaddress = sys.argv[1]
            #remove entry from banlist
            if is_valid_ipv4(ipaddress):
                path = check_banlist_path()
                fileopen = open(path, "r")
                data = fileopen.read()
                data = data.replace(ipaddress + "\n", "")
                filewrite = open(path, "w")
                filewrite.write(data)
                filewrite.close()
                fileopen.close()
                #remove entry from routing table
                delete_route(ipaddress)
            else:
                write_console("[!] Not a valid IP Address. Exiting.")
                sys.exit()
        #
        except IndexError:
            write_console(f"banlist path: {str(globals.g_banlist)}")
            write_console("Description: Simple removal of IP address from banned sites.")
            write_console("[!] Usage: UnBan.exe <ip_address_to_ban>")


if __name__ == "__main__":
    if is_windows_os is True:
        windows_route()
    #
    if is_posix_os is True:
        linux_route()
