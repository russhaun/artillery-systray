
#
# eventual home for checking some base files for security configurations
#
import re
import os
from src.config import harden_check, ssh_root_check_enabled, ssh_default_port_check_enabled, is_posix_os, is_windows_os
from src.email_handler import warn_the_good_guys
from src.core import *
if is_windows_os is True:
    from src.win_func import insecure_service_check
# flag warnings, base is nothing
warning = ""


def linux_harden_check():
    if os.path.isfile("/etc/ssh/sshd_config"):
        fileopen = open("/etc/ssh/sshd_config", "r")
        data = fileopen.read()
        if ssh_root_check_enabled is True:
            match = re.search("RootLogin yes", data)
            # if we permit root logins trigger alert
            if match:
                # trigger warning if match
                warning = warning + \
                        "[!] Issue identified: /etc/ssh/sshd_config allows RootLogin. An attacker can gain root access to the system if password is guessed. Recommendation: Change RootLogin yes to RootLogin no\n\r\n\r"
            match = re.search(r"Port 22\b", data)
            if match:
                if ssh_default_port_check_enabled is True:
                    # trigger warning if match
                    warning = warning + "[!] Issue identified: /etc/ssh/sshd_config. SSH is running on the default port 22. An attacker commonly scans for these type of ports. Recommendation: Change the port to something high that doesn't get picked up by typical port scanners.\n\r\n\r"
            # add SSH detection for password auth
            match = re.search("PasswordAuthentication yes", data)
            # if password authentication is used
            if match:
                warning = warning + \
                    "[!] Issue identified: Password authentication enabled. An attacker may be able to brute force weak passwords.\n\r\n\r"
                match = re.search("Protocol 1|Protocol 2,1", data)
            #
            if match:
                # triggered
                warning = warning + \
                    "[!] Issue identified: SSH Protocol 1 enabled which is potentially vulnerable to MiTM attacks. https://www.kb.cert.org/vuls/id/684820\n\r\n\r"
        #
        # check ftp config
        #
        if os.path.isfile("/etc/vsftpd.conf"):
            fileopen = open("/etc/vsftpd.conf", "r")
            data = fileopen.read()
            match = re.search("anonymous_enable=YES", data)
            if match:
                # trigger warning if match
                warning = warning + \
                    "[!] Issue identified: /etc/vsftpd.conf allows Anonymous login. An attacker can gain a foothold to the system with absolutel zero effort. Recommendation: Change anonymous_enable yes to anonymous_enable no\n\r\n\r"
        #
        # check /var/www permissions
        #
        if os.path.isdir("/var/www/"):
            for path, subdirs, files in os.walk("/var/www/"):
                for name in files:
                    trigger_warning = 0
                    filename = os.path.join(path, name)
                    if os.path.isfile(filename):
                        # check permission
                        check_perm = os.stat(filename)
                        check_perm = str(check_perm)
                        match = re.search("st_uid=0", check_perm)
                        if not match:
                            trigger_warning = 1
                        match = re.search("st_gid=0", check_perm)
                        if not match:
                            trigger_warning = 1
                        # if we trigger on vuln
                        if trigger_warning == 1:
                            warning = warning + \
                                "Issue identified: %s permissions are not set to root. If an attacker compromises the system and is running under the Apache user account, could view these files. Recommendation: Change the permission of %s to root:root. Command: chown root:root %s\n\n" % (
                                    filename, filename, filename)

        #
        # if we had warnings then trigger alert
        #
        if len(warning) > 1:
            subject = "[!] Insecure configuration detected on filesystem: "
            warn_the_good_guys(subject, subject + warning)


def hardening_checks():
    if harden_check is True:
        write_console("[*] Checking system hardening.")
        write_log("[*] Checking system hardening.")
        if is_windows_os is True:
            write_console('[*] Loading service checks.....')
            write_log('[*] Loading service checks.....')
            insecure_service_check()
        if is_posix_os is True:
            write_console('[*] Loading service checks.....')
            write_log('[*] Loading service checks.....')
            linux_harden_check()
