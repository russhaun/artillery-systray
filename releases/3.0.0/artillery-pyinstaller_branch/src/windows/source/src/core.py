# #################################core module for reusable / central code####################################
#

import shutil
import time
import os
import re
import subprocess
import socket
import sys
import requests
from urllib.request import Request, urlopen
import logging
import logging.handlers
import datetime
import signal
from string import *
from . import globals
from . import config
from pathlib import PureWindowsPath, PurePosixPath

def init_globals() -> None:
    '''Defines global variables for windows and linux.
        uses sys.platform to retrive type of system'''
    if 'win32' in sys.platform:
        #programfolder = config.ProgramFolder
        programfolder = os.environ["PROGRAMFILES(X86)"]
        #globals.g_appname = config.AppName
        globals.g_appname = "Artillery"
        #globals.g_apppath = config.AppPath
        globals.g_apppath = PureWindowsPath(programfolder + "\\Artillery")
        globals.g_appfile = PureWindowsPath(globals.g_apppath, "artillery.exe")
        globals.g_configfile = PureWindowsPath(globals.g_apppath, "config")
        globals.g_banlist = PureWindowsPath(globals.g_apppath, "banlist.txt")
        globals.g_localbanlist = PureWindowsPath(globals.g_apppath, "localbanlist.txt")
        globals.g_win_src = PureWindowsPath(globals.g_apppath, "src\\windows")
        globals.g_eventdll = PureWindowsPath(globals.g_win_src, "ArtilleryEvents.dll")
        globals.g_logpath = PureWindowsPath(globals.g_apppath, "logs")
        globals.g_alertlog = PureWindowsPath(globals.g_apppath, "logs\\alerts.log")
        globals.g_pidfile = PureWindowsPath(globals.g_apppath, "pid.txt")
        globals.g_batch = PureWindowsPath(globals.g_apppath, "artillery_start.bat")
        globals.g_icon_path = PureWindowsPath(globals.g_apppath, "src\\icons")
        globals.g_database = PureWindowsPath(globals.g_apppath, "database\\temp.database")
        globals.g_hostname = ""
        globals.g_host_os = ""
        globals.g_syspath = ""
        #consolidated nix* variants

    if ('linux' or 'linux2' or 'darwin') in sys.platform:
        globals.g_apppath = "/var/artillery"
        globals.g_appfile = globals.g_apppath + "/artillery.py"
        globals.g_configfile = globals.g_apppath + "/config"
        globals.g_banlist = globals.g_apppath + "/banlist.txt"
        globals.g_localbanlist = globals.g_apppath + "/localbanlist.txt"


# grab the current time
def grab_time() -> str:
    '''grabs current time and returns it in %Y-%m-%d %H:%M:%S format'''
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def gethostname() -> str:
    '''grabs hostname and retuns it'''
    return socket.gethostname()


def convert_to_classc(param):
    '''converts an ipaddr to cover whole block. ex: if the attacker addr is 192.168.2.1
    the resulting entry put in banlist is 192.168.2.0/24. Therefor blocking the entire range'''
    ipparts = param.split('.')
    classc = ""
    if len(ipparts) == 4:
        classc = ipparts[0] + "." + ipparts[1] + "." + ipparts[2] + ".0/24"
    return classc


def ban(ip):
    '''checks to see if a certain ip is on the banlist already if not adds it.
    On linux will add entry to iptables. On windows adds to routing table'''
    # ip check routine to see if its a valid IP address
    ip = ip.rstrip()
    #honeypot_ban = config.honeypot_ban_enabled
    #classc_ban = config.ban_class_c
    ban_check = config.read_config("HONEYPOT_BAN").lower()
    ban_classc = config.read_config("HONEYPOT_BAN_CLASSC").lower()
    test_ip = ip
    if "/" in test_ip:
        test_ip = test_ip.split("/")[0]
    if is_whitelisted_ip(test_ip):
        write_log("Not banning IP %s, whitelisted" % test_ip)
        return
    if ban_check == "on":
        if not ip.startswith("#"):
            if not ip.startswith("0."):
                if is_valid_ipv4(ip.strip()):
                    # if we are running nix variant then trigger ban through
                    # iptables
                    if is_posix():
                        if not is_already_banned(ip):
                            if ban_classc == "on":

                                ip = convert_to_classc(ip)
                                subprocess.Popen(
                                    "iptables -I ARTILLERY 1 -s %s -j DROP" % ip, shell=True).wait()
                            iptables_logprefix = config.read_config("HONEYPOT_BAN_LOG_PREFIX")
                            if iptables_logprefix != "":
                                subprocess.Popen("iptables -I ARTILLERY 1 -s %s -j LOG --log-prefix \"%s\"" % (ip, iptables_logprefix), shell=True).wait()

                    # if running windows then route attacker to some bs address.
                    if is_windows():
                        from .event_log import write_windows_eventlog, warning
                        #lets try and write an event log
                        write_windows_eventlog("Artillery", 200, warning, False, None)
                        #now lets block em or mess with em route somewhere else?
                        routecmd = "route ADD %s MASK 255.255.255.255 10.255.255.255"
                        if ban_check == 'on':
                            if ban_classc == "on":
                                #bind_ip =read_config('')
                                ip = convert_to_classc(ip)
                                ipparts = ip.split(".")
                                routecmd = "route ADD %s.%s.%s.0 MASK 255.255.255.0 10.255.255.255" % (ipparts[0], ipparts[1], ipparts[2])
                                subprocess.Popen("%s" % (routecmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                            else:
                                # or use the old way and just ban the individual ip
                                subprocess.Popen(routecmd % (ip), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

                    # add new IP to banlist
                    fileopen = open(globals.g_banlist, "r")
                    data = fileopen.read()
                    if ip not in data:
                        filewrite = open(globals.g_banlist, "a")
                        filewrite.write(ip + "\n")
                        filewrite.close()
                        sort_banlist()

                    if config.read_config("LOCAL_BANLIST").lower() == "on":

                        fileopen = open(globals.g_localbanlist, "r")
                        data = fileopen.read()
                        if ip not in data:
                            filewrite = open(globals.g_localbanlist, "a")
                            filewrite.write(ip + "\n")
                            filewrite.close()


def update():
    '''updates artillery on linux platforms'''
    if is_posix():
        write_log("Running auto update (git pull)")
        write_console("Running auto update (git pull)")

        if os.path.isdir(globals.g_apppath + "/.svn"):
            print(
                "[!] Old installation detected that uses subversion. Fixing and moving to github.")
            try:
                if len(globals.g_apppath) > 1:
                    shutil.rmtree(globals.g_apppath)
                subprocess.Popen(
                    "git clone https://github.com/binarydefense/artillery", shell=True).wait()
            except:
                print(
                    "[!] Something failed. Please type 'git clone https://github.com/binarydefense/artillery %s' to fix!" % globals.g_apppath)

        #subprocess.Popen("cd %s;git pull" % globals.g_apppath,
        #                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        update_cmd = execOScmd("cd %s; git pull" % globals.g_apppath)
        errorfound = False
        abortfound = False
        errormsg = ""
        for l in update_cmd:
            errormsg += "%s\n" % l
            if "error:" in l:
                errorfound = True
            if "Aborting" in l:
                abortfound = True
        if errorfound and abortfound:
            msg = "Error updating artillery, git pull was aborted. Error:\n%s" % errormsg
            write_log(msg, 2)
            write_console(msg)
            msg = "I will make a cop of the config file, run git stash, and restore config file"
            write_log(msg, 2)
            write_console(msg)
            saveconfig = "cp '%s' '%s.old'" % (globals.g_configfile, globals.g_configfile)
            execOScmd(saveconfig)
            gitstash = "git stash"
            execOScmd(gitstash)
            gitpull = "git pull"
            newpull = execOScmd(gitpull)
            restoreconfig = "cp '%s.old' '%s'" % (globals.g_configfile, globals.g_configfile)
            execOScmd(restoreconfig)
            pullmsg = ""
            for l in newpull:
                pullmsg += "%s\n" % l
            msg = "Tried to fix git pull issue. Git pull now says:"
            write_log(msg, 2)
            write_console(msg)
            write_log(pullmsg, 2)
            write_console(pullmsg)

        else:
            msg = "Output 'git pull':\n%s" % errormsg
            write_log(msg)
    if is_windows():
        pass


def addressInNetwork(ip, net):
    """
    returns true if the ip is in a given network
    """
    try:
        ipaddr = int(''.join(['%02x' % int(x) for x in ip.split('.')]), 16)
        netstr, bits = net.split('/')
        netaddr = int(''.join(['%02x' % int(x) for x in netstr.split('.')]), 16)
        mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
        return (ipaddr & mask) == (netaddr & mask)
    except:
        return False


def is_whitelisted_ip(ip):
    '''checks to see if a certain ip is on the whitelist and returns it'''
    # grab ips
    ipaddr = str(ip)
    whitelist = config.read_config("WHITELIST_IP")
    whitelist = whitelist.split(',')
    for site in whitelist:
        if site.find("/") < 0:
            if site.find(ipaddr) >= 0:
                return True
            else:
                continue
        if addressInNetwork(ipaddr, site):
            return True
    return False


def is_valid_ipv4(ip):
    '''validate that its an actual ip address versus something else stupid'''
    # if IP is cidr, strip net
    if "/" in ip:
        ipparts = ip.split("/")
        ip = ipparts[0]
    if not ip.startswith("#"):
        pattern = re.compile(r"""
    ^
    (?:
      # Dotted variants:
      (?:
        # Decimal 1-255 (no leading 0's)
        [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
      |
        0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
      |
        0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
      )
      (?:                  # Repeat 0-3 times, separated by a dot
        \.
        (?:
          [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
        |
          0x0*[0-9a-f]{1,2}
        |
          0+[1-3]?[0-7]{0,2}
        )
      ){0,3}
    |
      0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
    |
      0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
    |
      # Decimal notation, 1-4294967295:
      429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
      42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
      4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
    )
    $
    """, re.VERBOSE | re.IGNORECASE)
        return pattern.match(ip) is not None


def check_banlist_path():
    '''checks for banlist.txt if not found attempts to create one with header'''
    path = ""
    if is_posix():
        #if os.path.isfile("banlist.txt"):
        #    path = "banlist.txt"

        if os.path.isfile(globals.g_banlist):
            path = globals.g_banlist

        # if path is blank then try making the file
        if path == "":
            if os.path.isdir(globals.g_apppath):
                filewrite = open(globals.g_banlist, "w")
                filewrite.write(
                    "#\n#\n#\n# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed\n# https://www.binarydefense.com\n#\n# Note that this is for public use only.\n# The ATIF feed may not be used for commercial resale or in products that are charging fees for such services.\n# Use of these feeds for commerical (having others pay for a service) use is strictly prohibited.\n#\n#\n#\n")
                filewrite.close()
                path = globals.g_banlist
    #changed path to be more consistant across windows versions
    if is_windows():
        #program_files = os.environ["PROGRAMFILES(X86)"]
        if os.path.isfile(globals.g_banlist):
            # grab the path
            path = globals.g_banlist
        if path == "":
            if os.path.isdir(globals.g_apppath):
                path = globals.g_apppath
                filewrite = open(
                    globals.g_banlist, "w")
                filewrite.write(
                    "#\n#\n#\n# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed\n# https://www.binarydefense.com\n#\n# Note that this is for public use only.\n# The ATIF feed may not be used for commercial resale or in products that are charging fees for such services.\n# Use of these feeds for commerical (having others pay for a service) use is strictly prohibited.\n#\n#\n#\n")
                filewrite.close()
    return path


def is_posix():
    '''returns if platform is posix related'''
    return os.name == "posix"


def is_windows():
    '''returns if platform is Windows related'''
    return os.name == "nt"


def execOScmd(cmd, logmsg=""):
    '''execute OS command and to wait until it's finished'''
    if logmsg != "":
        write_log("execOSCmd: %s" % (logmsg))
    p = subprocess.Popen('%s' % cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True)
    outputobj = iter(p.stdout.readline, b'')
    outputlines = []
    for l in outputobj:
        thisline = ""
        try:
            thisline = l.decode()
        except:
            try:
                thisline = l.decode('utf8')
            except:
                thisline = "<unable to decode>"
        #print(thisline)
        outputlines.append(thisline.replace('\\n', '').replace("'", ""))
    return outputlines


def execOScmdAsync(cmdarray):
    '''execute OS commands Asynchronously this one takes an array
    first element is application, arguments are in additional array elements'''
    p = subprocess.Popen(cmdarray)
    #p.terminate()
    return


def create_empty_file(filepath):
    '''creates an empty file at the given file path'''
    filewrite = open(filepath, "w")
    filewrite.write("")
    filewrite.close()


def write_banlist_banner(filepath):
    '''writes out banlist.txt header to file'''
    filewrite = open(filepath, "w")
    banner = """#
#
#
# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed
# https://www.binarydefense.com
#
# Note that this is for public use only.
# The ATIF feed may not be used for commercial resale or in products that are charging fees for such services.
# Use of these feeds for commerical (having others pay for a service) use is strictly prohibited.
#
#
#
"""
    filewrite.write(banner)
    filewrite.close()


def create_iptables_subset():
    '''reads in ip info from banlist and other sources and adds them to to a fresh iptables chain
    for artillery'''
    if is_posix():
        ban_check = config.read_config("HONEYPOT_BAN").lower()
        if ban_check == "on":
            # remove previous entry if it already exists
            execOScmd("iptables -D INPUT -j ARTILLERY", "Deleting ARTILLERY IPTables Chain")
            # create new chain
            write_log("Flushing iptables chain, creating a new one")
            execOScmd("iptables -N ARTILLERY -w 3")
            execOScmd("iptables -F ARTILLERY -w 3")
            execOScmd("iptables -I INPUT -j ARTILLERY -w 3")

    bannedips = []

    if not os.path.isfile(globals.g_banlist):
        create_empty_file(globals.g_banlist)
        write_banlist_banner(globals.g_banlist)

    banfile = open(globals.g_banlist, "r").readlines()
    write_log("Read %d lines in '%s'" % (len(banfile), globals.g_banlist))

    for ip in banfile:
        if not ip in bannedips:
            bannedips.append(ip)

    if config.read_config("LOCAL_BANLIST").lower() == "on":
        if not os.path.isfile(globals.g_localbanlist):
            create_empty_file(globals.g_localbanlist)
            write_banlist_banner(globals.g_localbanlist)
        localbanfile = open(globals.g_localbanlist, "r").readlines()
        write_log("Read %d lines in '%s'" % (len(localbanfile), globals.g_localbanlist))
        for ip in localbanfile:
            if not ip in bannedips:
                bannedips.append(ip)

    # if we are banning
    banlist = []
    if config.read_config("HONEYPOT_BAN").lower() == "on":
        # iterate through lines from ban file(s) and ban them if not already
        # banned
        for ip in bannedips:
            if not ip.startswith("#") and not ip.replace(" ", "") == "":
                ip = ip.strip()
                if ip != "" and not ":" in ip:
                    test_ip = ip
                if "/" in test_ip:
                    test_ip = test_ip.split("/")[0]
                if not is_whitelisted_ip(test_ip):
                    if is_posix():
                        if not ip.startswith("0."):
                            if is_valid_ipv4(ip.strip()):
                                if config.read_config("HONEYPOT_BAN_CLASSC").lower() == "on":
                                    if not ip.endswith("/24"):
                                        ip = convert_to_classc(ip)
                                    banlist.append(ip)
                    if is_windows():

                        ban(ip)
                    else:
                        write_log("Not banning IP %s, whitelisted" % ip)
        if config.read_config("LOCAL_BANLIST").lower() == "on":\

            localbanfile = open(globals.g_localbanlist, "r").readlines()

    if len(banlist) > 0:

        # convert banlist into unique list
        write_log("Filtering duplicate entries in banlist")
        set_banlist = set(banlist)
        unique_banlist = (list(set_banlist))
        entries_at_once = 750
        total_nr = len(unique_banlist)
        write_log("Mass loading %d unique entries from banlist(s)" % total_nr)
        write_console("    Mass loading %d unique entries from banlist(s)" % total_nr)
        nr_of_lists = int(len(unique_banlist) / entries_at_once) + 1
        iplists = get_sublists(unique_banlist, nr_of_lists)
        listindex = 1
        logindex = 1
        logthreshold = 25
        if len(iplists) > 1000:
            logthreshold = 100
        total_added = 0
        for iplist in iplists:
            ips_to_block = ','.join(iplist)
            massloadcmd = "iptables -I ARTILLERY -s %s -j DROP -w 3" % ips_to_block
            subprocess.Popen(massloadcmd, shell=True).wait()
            iptables_logprefix = config.read_config("HONEYPOT_BAN_LOG_PREFIX")
            if iptables_logprefix != "":
                massloadcmd = "iptables -I ARTILLERY -s %s -j LOG --log-prefix \"%s\" -w 3" % (ips_to_block, iptables_logprefix)
                subprocess.Popen(massloadcmd, shell=True).wait()
            total_added += len(iplist)
            write_log("%d/%d - Added %d/%d IP entries to iptables chain." % (listindex, len(iplists), total_added, total_nr))
            if logindex >= logthreshold:
                write_console("    %d/%d : Update: Added %d/%d entries to iptables chain" % (listindex, len(iplists), total_added, total_nr))
                logindex = 0
            listindex += 1
            logindex += 1
        write_console("    %d/%d : Done: Added %d/%d entries to iptables chain, thank you for waiting." % (listindex-1, len(iplists), total_added, total_nr))


def get_sublists(original_list, number_of_sub_list_wanted):
    '''gets and returns x num of list based on original input'''
    sublists = list()
    for sub_list_count in range(number_of_sub_list_wanted):
        sublists.append(original_list[sub_list_count::number_of_sub_list_wanted])
    return sublists


def is_already_banned(ip) -> bool:
    '''checks to see if an ip is already banned and returns True or False'''
    ban_check = config.read_config("HONEYPOT_BAN").lower()
    if ban_check == "on":
        if is_posix():
            proc = subprocess.Popen("iptables -L ARTILLERY -n --line-numbers",
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if is_windows():
            proc = subprocess.Popen("route print",
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        iptablesbanlist = proc.stdout.readlines()
        ban_classc = config.read_config("HONEYPOT_BAN_CLASSC").lower()
        if ban_classc == "on":
            ip = convert_to_classc(ip)
        if ip in iptablesbanlist:

            return True
        else:
            return False
    else:
        return False


def is_valid_ip(ip) -> bool:
    '''returns True if is a valid ip address'''
    return is_valid_ipv4(ip)


def bin2ip(b):
    '''convert a binary string into an IP address'''
    ip = ""
    for i in range(0, len(b), 8):
        ip += str(int(b[i:i + 8], 2)) + "."
    return ip[:-1]


def ip2bin(ip):
    '''convert an IP address from its dotted-quad format to its 32 binary digit representation'''
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q), 8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b


def dec2bin(n, d=None):
    '''convert a decimal number to binary representation
    if d is specified, left-pad the binary number with 0s to that length'''
    s = ""
    while n > 0:
        if n & 1:
            s = "1" + s
        else:
            s = "0" + s
        n >>= 1

    if d is not None:
        while len(s) < d:
            s = "0" + s
    if s == "":
        s = "0"
    return s


def printCIDR(attacker_ip):
    '''print a list of IP addresses based on the CIDR block specified'''
    trigger = 0
    whitelist = config.read_config("WHITELIST_IP")
    whitelist = whitelist.split(",")
    for c in whitelist:
        match = re.search("/", c)
        if match:
            parts = c.split("/")
            baseIP = ip2bin(parts[0])
            subnet = int(parts[1])
            # Python string-slicing weirdness:
            # if a subnet of 32 was specified simply print the single IP
            if subnet == 32:
                ipaddr = bin2ip(baseIP)
            # for any other size subnet, print a list of IP addresses by concatenating
            # the prefix with each of the suffixes in the subnet
            else:
                ipPrefix = baseIP[:-(32 - subnet)]
                for i in range(2**(32 - subnet)):
                    ipaddr = bin2ip(ipPrefix + dec2bin(i, (32 - subnet)))
                    ip_check = is_valid_ip(ipaddr)
                    # if the ip isnt messed up then do this
                    if ip_check != False:
                        # compare c (whitelisted IP) to subnet IP address
                        # whitelist
                        if c == ipaddr:
                            # if we equal each other then trigger that we are
                            # whitelisted
                            trigger = 1

    # return the trigger - 1 = whitelisted 0 = not found in whitelist
    return trigger


def threat_server():
    public_http = config.read_config("THREAT_LOCATION")
    if os.path.isdir(public_http):
        banfiles = config.read_config("THREAT_FILE")
        if banfiles == "":
            banfiles = globals.g_banfile
        banfileparts = banfiles.split(",")
        while 1:
            for banfile in banfileparts:
                thisfile = globals.g_apppath + "/" + banfile
                subprocess.Popen("cp '%s' '%s'" % (thisfile, public_http), shell=True).wait()
                #write_log("ThreatServer: Copy '%s' to '%s'" % (thisfile, public_http))
            time.sleep(300)


def syslog(message, alerttype):
    """
    function to handle various logging methods availible. writes to SYSLOG, Remote SYSLOG, FILE
    """
    type = config.read_config("SYSLOG_TYPE")
    if type == None:
        type = "FILE"
    alertindicator = ""
    if alerttype == -1:
        alertindicator = ""
    elif alerttype == 0:
        alertindicator = "[INFO]"
    elif alerttype == 1:
        alertindicator = "[WARN]"
    elif alerttype == 2:
        alertindicator = "[ERROR]"

    # if we are sending remote syslog
    if type == "remote" or "REMOTE":

        import socket
        FACILITY = {
            'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
            'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
            'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
            'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
            'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
        }

        LEVEL = {
            'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3,
            'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
        }

        def syslog_send(
            message, level=LEVEL['notice'], facility=FACILITY['daemon'],
                        host='localhost', port=514):

            # Send syslog UDP packet to given host and port.
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = '<%d>%s' % (level + facility * 8, message + "\n")
            sock.sendto(data.encode("ascii"), (host, port))
            sock.close()

        # send the syslog message
        remote_syslog = config.read_config("SYSLOG_REMOTE_HOST")
        remote_port = int(config.read_config("SYSLOG_REMOTE_PORT"))
        syslogmsg = message
        if alertindicator != "":
            syslogmsg = "Artillery%s: %s" % (alertindicator, message)
        #syslogmsg = "%s %s Artillery: %s" % (grab_time(), alertindicator, message)
        syslog_send(syslogmsg, host=remote_syslog, port=remote_port)

    # if we are sending local syslog messages
    if type == "local" or "LOCAL":
        my_logger = logging.getLogger('Artillery')
        my_logger.setLevel(logging.DEBUG)
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        my_logger.addHandler(handler)
        for line in message.splitlines():
            if alertindicator != "":
                my_logger.critical("Artillery%s: %s\n" % (alertindicator, line))
                #my_logger.critical("%s %s Artillery: %s\n" % (grab_time(), alertindicator, line))
            else:
                my_logger.critical("%s\n" % line)

    # if we don't want to use local syslog and just write to file in
    # logs/alerts.log
    if type == "file" or "FILE":
        if not os.path.isdir("%s/logs" % globals.g_apppath):
            os.makedirs("%s/logs" % globals.g_apppath)

        if not os.path.isfile("%s/logs/alerts.log" % globals.g_apppath):
            filewrite = open("%s/logs/alerts.log" % globals.g_apppath, "w")
            filewrite.write("***** Artillery Alerts Log *****\n")
            filewrite.close()

        filewrite = open("%s/logs/alerts.log" % globals.g_apppath, "a")
        filewrite.write("Artillery%s: %s\n" % (alertindicator, message))
        filewrite.close()


def write_console(alert) -> None:
    '''writes alerts to console window'''
    if config.is_config_enabled("CONSOLE_LOGGING"):
        alertlines = alert.split("\n")
        for alertline in alertlines:
            print("%s: %s" % (grab_time(), alertline))
    return


def write_log(alert, alerttype=0):
    """writes a log depending on platform. On linux it uses syslog func. On windows writes to alerts.log
     """
    if is_posix():
        syslog(alert, alerttype)
    #changed path to be more consistant across windows versions
    if is_windows():
        program_files = os.environ["PROGRAMFILES(X86)"]
        if not os.path.isdir("%s\\logs" % globals.g_apppath):
            os.makedirs("%s\\logs" % globals.g_apppath)
        if not os.path.isfile("%s\\logs\\alerts.log" % globals.g_apppath):
            filewrite = open(
                "%s\\logs\\alerts.log" % globals.g_apppath, "w")
            filewrite.write("***** Artillery Alerts Log *****\n")
            filewrite.close()
        filewrite = open("%s\\logs\\alerts.log" % globals.g_apppath, "a")
        filewrite.write(alert + "\n")
        filewrite.close()


def kill_artillery() -> None:
    ''' kill running instances of artillery'''
    try:
        proc = subprocess.Popen(
            "ps -A x | grep artiller[y]", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        pid, err = proc.communicate()
        pid = [int(x.strip()) for line in pid.split()
               for x in line.split() if int(x.isdigit())]
        # try:
        # pid = int(pid[0])
        # except:
        # depends on OS on integer
        # pid = int(pid[2])
        for i in pid:
            write_log("Killing the old Artillery process...")
            print("[!] %s: Killing Old Artillery Process...." % (grab_time()))
            os.kill(i, signal.SIGKILL)

    except Exception as e:
        #print("caught exception")
        print(e)


def cleanup_artillery() -> None:
    ban_check = config.read_config("HONEYPOT_BAN").lower()
    if ban_check == "on":
        subprocess.Popen("iptables -D INPUT -j ARTILLERY",
                         stdout=subprocess.PIP, stderr=subprocess.PIPE, shell=True)
        subprocess.Popen("iptables -X ARTILLERY",
                         stdout=subprocess.PIP, stderr=subprocess.PIPE, shell=True)
        return 0


def refresh_log() -> None:
    '''overwrite artillery banlist after certain time interval
        with the value retrived from config file for artillery_refresh '''
    while 1:
        interval = config.read_config("ARTILLERY_REFRESH")
        try:
            interval = int(interval)
        except:
            # if the interval was not an integer, then just pass and don't do
            # it again
            break
        # sleep until interval is up
        time.sleep(interval)
        write_console("clearing banlist.txt")
        # overwrite the log with nothing
        create_empty_file(globals.g_banlist)
        write_banlist_banner(globals.g_banlist)
    #return


def format_ips(urls)->None:
    '''format the ip addresses and check to ensure they aren't duplicates'''
    write_log("[*] Getting unique entries.")
    write_console("[*] Getting unique entries.")
    line_number = 0
    uniquenewentries = 0
    u_list = []
    ips_lst = []
    ips = ""
    f = []
    
    for url in urls:
        try:
            write_log("Grabbing feed from '%s'" % (str(url)))
            if url.startswith("http"):
                req = urlopen(url)
                with req as file_to_read:
                    line = file_to_read.readlines()
                    for item in line:
                        ips_lst.append(item)
                        f.append(item)
        except Exception as err:
            if err == '404':
                # Error 404, page not found!
                write_log(f"HTTPError: Error 404, URL {url} not found.")
            elif err == '403':
                print("wrong headers were sent")
            else:
                if is_windows():
                    msg = format(err)
                    msg_to_string =  f"[!] Received URL Error trying to download feed from {url} Reason: {msg}"
                    print(msg_to_string)
                    write_log(msg_to_string)
                if is_posix():
                    msg = format(err)
                    write_log(f"Received URL Error trying to download feed from {url} Reason: {msg}",1)
    
    for line in f:
        line = line.decode('UTF-8')
        ips = ips + line + "\n"
        ips_lst.append(line)
        
    try:
        if is_windows():
            fileopen = open(globals.g_banlist, "r").read()
            # write the file
            filewrite = open(globals.g_banlist, "a")
        if is_posix():
            fileopen = open(globals.g_banlist, "r").read()
                # write the file
            filewrite = open(globals.g_banlist, "a")
          
        for line in ips_lst:
            try:
                #decode line might be in bytes
                line = line.decode('UTF-8')
                line = line.rstrip("\n")
            except:
                #if not its a normal str
                line = line.rstrip("\n")
            if "ALL:" in line:
                try:
                    line = line.split(" ")[1]
                except:
                    pass
            if not "#" in line:
                if not "//" in line:
                    if config.read_config("HONEYPOT_BAN_CLASSC").lower() == "on":
                        line = convert_to_classc(line)
                    if not line in fileopen:
                        if not line.startswith("0."):
                            
                            if is_valid_ipv4(line.strip()):
                                #try:
                                filewrite.write(line + "\n")
                                u_list.append(line)
                                uniquenewentries += 1
                                line_number += 1
        #
        #
        filewrite.close()
        #write_log("[*] Processing new entries.")
        #current_time = grab_time()
        #bar_txt = current_time +":"+" [*] Processing new entries "
        #if config.is_config_enabled('CONSOLE_LOGGING'):
        #    with Bar(bar_txt, fill= "*",max= uniquenewentries) as bar:
            #with MoonSpinner(bar_txt) as bar:
        #        for i in range(uniquenewentries):
                    #time.sleep(0.01)
        #            bar.next()
    #
    except Exception as err:
        write_console(f"Error identified as: {str(err)} with line: {str(line)}at line #: {line_number}")
    #
    #
    write_log("[*] Done creating new banlist from source feeds.")
    ban_file = len(fileopen)
    #remove lines fron banlist header
    final_count = ban_file - 13
    write_console(f"[*] Total of {str(final_count)} entries in banlist")
    write_console(f"[*] Added {str(uniquenewentries)} entries to banlist")
    write_log(f"[*] Total of {str(final_count)} entries in banlist")
    write_log(f"Added {str(uniquenewentries)} entries to banlist")
    sort_banlist()


def pull_source_feeds():
    '''update threat intelligence feed with other sources.'''
    write_log("[*] Pulling from source feeds please wait.......")
    write_console("[*] Pulling from source feeds please wait.......")
    while 1:
        url_list = []
        counter = 0
        # if we are using source feeds
        if config.read_config("SOURCE_FEEDS").lower() == "on":
            urls = ["http://rules.emergingthreats.net/blockrules/compromised-ips.txt", "http://lists.blocklist.de/lists/apache.txt", "http://lists.blocklist.de/lists/ssh.txt"]
            #append all the addrs to our final list
            for url in urls:
                url_list.append(url)
            counter = 1
        # if we are using threat intelligence feeds
        if config.read_config("THREAT_INTELLIGENCE_FEED").lower() == "on":
            #grab the entries from config file
            threat_feed = config.read_config("THREAT_FEED")
            if threat_feed != "":
                threat_feed = threat_feed.split(",")
                for threats in threat_feed:
                    url_list.append(threats)
            counter = 1
        # if we used source feeds or ATIF
        if counter == 1:
            write_log("[*] Done pulling from source feeds.")
            format_ips(url_list)
            time.sleep(86400)  # sleep for 24 hours


def sort_banlist() -> None:
    '''sort banlist in decending order adding only unique ips '''
    if is_windows():
        ips = open(globals.g_banlist, "r").readlines()
    if is_posix():
        ips = open(globals.g_banlist, "r").readlines()

    banner = """#
#
#
# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed
# https://www.binarydefense.com
#
# Note that this is for public use only.
# The ATIF feed may not be used for commercial resale or in products that are charging fees for such services.
# Use of these feeds for commerical (having others pay for a service) use is strictly prohibited.
#
#
#
"""
    ip_filter = ""
    for ip in ips:
        if is_valid_ipv4(ip.strip()):
            if not ip.startswith("0.") and not ip == "":
                ip_filter = ip_filter + ip.rstrip() + "\n"
    ips = ip_filter
    ips = ips.replace(banner, "")
    ips = ips.replace(" ", "")
    ips = ips.split("\n")
    ips = [_f for _f in ips if _f]
    ips = list(filter(str.strip, ips))
    tempips = [socket.inet_aton(ip.split("/")[0]) for ip in ips]
    tempips.sort()
    tempips.reverse()
    if is_windows():
        filewrite = open(globals.g_banlist, "w")
    if is_posix():
        filewrite = open(globals.g_banlist, "w")
    ips2 = [socket.inet_ntoa(ip) for ip in tempips]
    ips_parsed = ""
    for ips in ips2:
        if not ips.startswith("0."):
            if ips.endswith(".0"):
                ips += "/24"
            ips_parsed = ips + "\n" + ips_parsed
    filewrite.write(banner + "\n" + ips_parsed)
    filewrite.close()
    return 0



init_globals()
