#!/usr/bin/python
#
# monitor ssh and ban
#
import time
import re
import os
from src.config import monitor_frequency, ssh_brute_attempts, banlist, is_posix_os
from src.core import write_log, write_console, is_valid_ipv4, is_whitelisted_ip, ban
from src.email_handler import warn_the_good_guys


def ssh_monitor(monitor_frequency: int) -> None:
    counter = 0
    while 1:
        # for debian base
        if os.path.isfile("/var/log/auth.log"):
            fileopen1 = open("/var/log/auth.log", "r")
            counter = 1

            # for OS X
            if os.path.isfile("/var/log/secure.log"):
                if counter == 0:
                    fileopen1 = open("/var/log/secure.log", "r")
                    counter = 1

        # for centOS
        if os.path.isfile("/var/log/secure"):
            if counter == 0:
                fileopen1 = open("/var/log/secure", "r")
                counter = 1

        # for Debian
        if os.path.isfile("/var/log/faillog"):
            if counter == 0:
                fileopen1 = open("/var/log/faillog", "r")
                counter = 1

        if not os.path.isfile(banlist):
            # create a blank file
            filewrite = open(banlist, "w")
            filewrite.write("")
            filewrite.close()

        try:
            # base ssh counter to see how many attempts we've had
            ssh_counter = 0
            counter = 0
            for line in fileopen1:
                counter = 0
                fileopen2 = open(banlist, "r")
                line = line.rstrip()
                # search for bad ssh
                match = re.search("Failed password for", line)
                if match:
                    ssh_counter = ssh_counter + 1
                    line = line.split(" ")
                    # pull ipaddress
                    ipaddress = line[-4]
                    if is_valid_ipv4(ipaddress):

                        # if its not a duplicate then ban that ass
                        if ssh_counter >= int(ssh_brute_attempts):
                            ban_list = fileopen2.read()
                            match = re.search(ipaddress, ban_list)
                            if match:
                                counter = 1
                                # reset SSH counter
                                ssh_counter = 0

                            # if counter is equal to 0 then we know that we
                            # need to ban
                            if counter == 0:
                                whitelist_match = is_whitelisted_ip(ipaddress)
                                if whitelist_match == 0:
                                    subject = "[!] Artillery has banned an SSH brute force. [!]"
                                    alert = "Artillery has blocked (blacklisted) the following IP for SSH brute forcing violations: " + ipaddress
                                    warn_the_good_guys(subject, alert)

                                    # do the actual ban, this is pulled from
                                    # src.core
                                    ban(ipaddress)
                                    ssh_counter = 0

                                    # wait one to make sure everything is
                                    # caught up
                                    time.sleep(1)
            # sleep for defined time
            time.sleep(monitor_frequency)

        except Exception as e:
            print("[*] An error in ssh monitor occured. Printing it out here: " + str(e))


def start_ssh_monitor():
    if is_posix_os is True:
        write_console("[*] Launching SSH Bruteforce monitor.")
        ssh_monitor(int(monitor_frequency))
