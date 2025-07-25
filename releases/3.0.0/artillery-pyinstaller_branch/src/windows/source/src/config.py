#
#
# import libs needed from core.py
#from src.core import *
import re
import os
import sys
import socket
#from src.core import  write_console, write_log, globals
from pathlib import PureWindowsPath, PurePosixPath


def is_posix():
    """
    returns true if posix platform
    """
    if ('linux' or 'linux2' or 'darwin') in sys.platform:
        #print(sys.platform)
        return True
    else:
        return False


def is_windows():
    """
    returns true if windows platform
    """
    if 'win32' in sys.platform:
        return True
    else:
        return False


is_windows_os = is_windows()
is_posix_os = is_posix()


def config_exists(param):
    '''check if a certain config parameter exists in the current config file'''
    path = get_config_path()
    fileopen = open(path, "r")
    paramfound = False
    for line in fileopen:
        if not line.startswith("#"):
            match = re.search(param + "=", line)
            if match:
                paramfound = True
    return paramfound


def get_config_path():
    '''grabs current config file location and returns path'''
    path = configfile
    return path


def read_config(param):
    '''reads config for specific value and returns it'''
    #if is_posix():
    path = get_config_path()
    fileopen = open(path, "r")
    for line in fileopen:
        if not line.startswith("#"):
            match = re.search(param + "=", line)
            if match:
                line = line.rstrip()
                line = line.replace('"', "")
                line = line.split("=")
                return line[1]


def is_config_enabled(param):
    """
    checks to see if a paticular config option is enabled or not and returns it
    """
    try:
        config = read_config(param).lower()
        return config in ("on", "yes")
    except AttributeError:
        return "off"


def check_config() -> None:
    '''Sane default settings built out into a dict to be used during config creation/updating'''
    configdefaults = {}
    configdefaults["MONITOR"] = ["OFF", "DETERMINE IF YOU WANT TO MONITOR OR NOT"]
    if is_posix():
        configdefaults["MONITOR_FOLDERS"] = ["\"/var/www\",\"/etc/\"", "THESE ARE THE FOLDERS TO MONITOR, TO ADD MORE, JUST DO \"/root\",\"/var/\", etc."]
    if is_windows_os is True:
        configdefaults["MONITOR_FOLDERS"] = ["c:\\temp"", ""c:\\windows\\temp", "THESE ARE THE FOLDERS TO MONITOR, TO ADD MORE, JUST DO ""c:\\path,c:\\other\\path, etc."]
    configdefaults["MONITOR_FREQUENCY"] = ["60", "BASED ON SECONDS, 2 = 2 seconds."]
    configdefaults["SYSTEM_HARDENING"] = ["OFF", "PERFORM CERTAIN SYSTEM HARDENING CHECKS"]
    configdefaults["SSH_DEFAULT_PORT_CHECK"] = ["ON", "CHECK/WARN IF SSH IS RUNNING ON PORT 22"]
    configdefaults["EXCLUDE"] = ["", "EXCLUDE CERTAIN DIRECTORIES OR FILES. USE FOR EXAMPLE: /etc/passwd,/etc/hosts.allow"]
    configdefaults["ENABLE_HONEYPOT"] = ["OFF", "TURN ON HONEYPOT"]
    configdefaults["HONEYPOT_BAN"] = ["OFF", "DO YOU WANT TO AUTOMATICALLY BAN ON THE HONEYPOT"]
    configdefaults["HONEYPOT_BAN_CLASSC"] = ["OFF", "WHEN BANNING, DO YOU WANT TO BAN ENTIRE CLASS C AT ONCE INSTEAD OF INDIVIDUAL IP ADDRESS"]
    configdefaults["HONEYPOT_BAN_LOG_PREFIX"] = ["", "PUT A PREFIX ON ALL BANNED IP ADDRESSES. HELPFUL FOR WHEN TRYING TO PARSE OR SHOW DETECTIONS THAT YOU ARE PIPING OFF TO OTHER SYSTEMS. WHEN SET, PREFIX IPTABLES LOG ENTRIES WITH THE PROVIDED TEXT"]
    configdefaults["WHITELIST_IP"] = ["127.0.0.1,localhost", "WHITELIST IP ADDRESSES, SPECIFY BY COMMAS ON WHAT IP ADDRESSES YOU WANT TO WHITELIST"]
    configdefaults["TCPPORTS"] = ["22,1433,8080,21,5060,5061,5900,25,110,1723,1337,10000,5800,44443,16993", "TCP PORTS TO SPAWN HONEYPOT FOR"]
    configdefaults["UDPPORTS"] = ["5060,5061,3478", "UDP PORTS TO SPAWN HONEYPOT FOR"]
    configdefaults["HONEYPOT_AUTOACCEPT"] = ["ON", "SHOULD THE HONEYPOT AUTOMATICALLY ADD ACCEPT RULES TO THE ARTILLERY CHAIN FOR ANY PORTS ITS LISTENING ON"]
    configdefaults["EMAIL_ALERTS"] = ["OFF", "SHOULD EMAIL ALERTS BE SENT"]
    configdefaults["SMTP_USERNAME"] = ["", "CURRENT SUPPORT IS FOR SMTP. ENTER YOUR USERNAME AND PASSWORD HERE FOR STARTTLS AUTHENTICATION. LEAVE BLANK FOR OPEN RELAY"]
    configdefaults["SMTP_PASSWORD"] = ["", "ENTER SMTP PASSWORD HERE"]
    configdefaults["2FA_PASS"] = ["", "2-FACTOR PASSWORD GOES HERE. IF ENABLED ON YOUR EMAIL ACCT. IF NOT IT SHOULD BE. THIS ASSUMES GOOGLE EMAIL"]
    configdefaults["ENABLE_2FA"] = ["OFF", " ENABLE 2-FACTOR AUTH. MUST RETRIEVE INDIVIDUAL PASS FROM GOOGLE ACCT FOR THIS INSTANCE. "]
    configdefaults["ALERT_USER_EMAIL"] = ["enter_your_email_address_here@localhost", "THIS IS WHO TO SEND THE ALERTS TO - EMAILS WILL BE SENT FROM ARTILLERY TO THIS ADDRESS"]
    configdefaults["SMTP_FROM"] = ["Artillery_Incident@localhost", "FOR SMTP ONLY HERE, THIS IS THE MAILTO"]
    configdefaults["SMTP_ADDRESS"] = ["smtp.gmail.com", "SMTP ADDRESS FOR SENDING EMAIL, DEFAULT IS GMAIL"]
    configdefaults["SMTP_PORT"] = ["587", "SMTP PORT FOR SENDING EMAILS DEFAULT IS GMAIL WITH STARTTLS"]
    configdefaults["EMAIL_TIMER"] = ["ON", "THIS WILL SEND EMAILS OUT DURING A CERTAIN FREQUENCY. IF THIS IS SET TO OFF, ALERTS WILL BE SENT IMMEDIATELY (CAN LEAD TO A LOT OF SPAM)"]
    configdefaults["EMAIL_FREQUENCY"] = ["600", "HOW OFTEN DO YOU WANT TO SEND EMAIL ALERTS (DEFAULT 10 MINUTES) - IN SECONDS"]
    configdefaults["SSH_BRUTE_MONITOR"] = ["ON", "DO YOU WANT TO MONITOR SSH BRUTE FORCE ATTEMPTS"]
    configdefaults["SSH_BRUTE_ATTEMPTS"] = ["4", "HOW MANY ATTEMPTS BEFORE YOU BAN"]
    configdefaults["FTP_BRUTE_MONITOR"] = ["OFF", "DO YOU WANT TO MONITOR FTP BRUTE FORCE ATTEMPTS"]
    configdefaults["FTP_BRUTE_ATTEMPTS"] = ["4", "HOW MANY ATTEMPTS BEFORE YOU BAN"]
    configdefaults["AUTO_UPDATE"] = ["OFF", "DO YOU WANT TO DO AUTOMATIC UPDATES - ON OR OFF. UPDATE_LOCATION must be set on windows"]
    if is_windows_os is True:
        configdefaults["UPDATE_LOCATION"] = ["path\\to\\files", "UPDATE FILES LOCATION ONLY VALID ON WINDOWS. MUST USE FULLY QUALIFIED PATH ex. c:\\path\\to\\files MUST BE READ\WRITEABLE"]
        configdefaults["UPDATE_FREQUENCY"] = ["604800", "UPDATE FREQUENCY, ONLY VALID ON WINDOWS (DEFAULT IS 7 DAYS)."]
    configdefaults["ANTI_DOS"] = ["OFF", "ANTI DOS WILL CONFIGURE MACHINE TO THROTTLE CONNECTIONS, TURN THIS OFF IF YOU DO NOT WANT TO USE"]
    configdefaults["ANTI_DOS_PORTS"] = ["80,443", "THESE ARE THE PORTS THAT WILL PROVIDE ANTI_DOS PROTECTION"]
    configdefaults["ANTI_DOS_THROTTLE_CONNECTIONS"] = ["50", "THIS WILL THROTTLE HOW MANY CONNECTIONS PER MINUTE ARE ALLOWED HOWEVER THE BUST WILL ENFORCE THIS"]
    configdefaults["ANTI_DOS_LIMIT_BURST"] = ["200", "THIS WILL ONLY ALLOW A CERTAIN BURST PER MINUTE THEN WILL ENFORCE AND NOT ALLOW ANYMORE TO CONNECT"]
    configdefaults["APACHE_MONITOR"] = ["OFF", "MONITOR LOGS ON AN APACHE SERVER"]
    configdefaults["ACCESS_LOG"] = ["/var/log/apache2/access.log", "THIS IS THE PATH FOR THE APACHE ACCESS LOG"]
    configdefaults["ERROR_LOG"] = ["/var/log/apache2/error.log", "THIS IS THE PATH FOR THE APACHE ERROR LOG"]
    configdefaults["BIND_INTERFACE"] = ["", "THIS ALLOWS YOU TO SPECIFY AN IP ADDRESS. LEAVE THIS BLANK TO BIND TO ALL INTERFACES."]
    configdefaults["THREAT_INTELLIGENCE_FEED"] = ["ON", "TURN ON INTELLIGENCE FEED, CALL TO https://www.binarydefense.com/banlist.txt IN ORDER TO GET ALREADY KNOWN MALICIOUS IP ADDRESSES. WILL PULL EVERY 24 HOURS"]
    configdefaults["THREAT_FEED"] = ["https://www.binarydefense.com/banlist.txt", "CONFIGURE THIS TO BE WHATEVER THREAT FEED YOU WANT BY DEFAULT IT WILL USE BINARY DEFENSE - NOTE YOU CAN SPECIFY MULTIPLE THREAT FEEDS BY DOING #http://urlthreatfeed1,http://urlthreadfeed2"]
    configdefaults["THREAT_SERVER"] = ["OFF", "A THREAT SERVER IS A SERVER THAT WILL COPY THE BANLIST.TXT TO A PUBLIC HTTP LOCATION TO BE PULLED BY OTHER ARTILLERY SERVER. THIS IS USED IF YOU DO NOT WANT TO USE THE STANDARD BINARY DEFENSE ONE."]
    configdefaults["THREAT_LOCATION"] = ["/var/www/", "PUBLIC LOCATION TO PULL VIA HTTP ON THE THREAT SERVER. NOTE THAT THREAT SERVER MUST BE SET TO ON"]
    configdefaults["THREAT_FILE"] = ["banlist.txt", "FILE TO COPY TO THREAT_LOCATION, TO ACT AS A THREAT_SERVER. CHANGE TO \"localbanlist.txt\" IF YOU HAVE ENABLED \"LOCAL_BANLIST\" AND WISH TO HOST YOUR LOCAL BANLIST. IF YOU WISH TO COPY BOTH FILES, SEPARATE THE FILES WITH A COMMA - f.i. \"banlist.txt,localbanlist.txt\""]
    configdefaults["LOCAL_BANLIST"] = ["OFF", "CREATE A SEPARATE LOCAL BANLIST FILE (USEFUL IF YOU'RE ALSO USING A THREAT FEED AND WANT TO HAVE A FILE THAT CONTAINS THE IPs THAT HAVE BEEN BANNED LOCALLY"]
    configdefaults["ROOT_CHECK"] = ["ON", "THIS CHECKS TO SEE WHAT PERMISSIONS ARE RUNNING AS ROOT IN A SSH SERVER DIRECTORY"]
    if is_posix_os is True:
        configdefaults["SYSLOG_TYPE"] = ["LOCAL", "Specify SYSLOG TYPE to be local, file or remote. LOCAL will pipe to syslog, REMOTE will pipe to remote SYSLOG, and file will send to alerts.log in local artillery directory"]
    if is_windows_os is True:
        configdefaults["SYSLOG_TYPE"] = ["FILE", "Specify SYSLOG TYPE to be local, file or remote. LOCAL will pipe to syslog, REMOTE will pipe to remote SYSLOG, and file will send to alerts.log in local artillery directory"]
    configdefaults["LOG_MESSAGE_ALERT"] = ["Artillery has detected an attack from %ip% for a connection on a honeypot port %port%", "ALERT LOG MESSAGES (You can use the following variables: %time%, %ip%, %port%)"]
    configdefaults["LOG_MESSAGE_BAN"] = ["Artillery has blocked (and blacklisted) an attack from %ip% for a connection to a honeypot restricted port %port%", "BAN LOG MESSAGES (You can use the following variables: %time%, %ip%, %port%)"]
    configdefaults["SYSLOG_REMOTE_HOST"] = ["192.168.0.1", "IF YOU SPECIFY SYSLOG TYPE TO REMOTE, SPECIFY A REMOTE SYSLOG SERVER TO SEND ALERTS TO"]
    configdefaults["SYSLOG_REMOTE_PORT"] = ["514", "IF YOU SPECIFY SYSLOG TYPE OF REMOTE, SEPCIFY A REMOTE SYSLOG PORT TO SEND ALERTS TO"]
    configdefaults["CONSOLE_LOGGING"] = ["ON", "TURN ON CONSOLE LOGGING"]
    if is_posix():
        configdefaults["RECYCLE_IPS"] = ["ON", "RECYCLE banlist.txt AFTER A CERTAIN AMOUNT OF TIME - THIS WILL WIPE ALL IP ADDRESSES AND START FROM SCRATCH AFTER A CERTAIN INTERVAL"]
    if is_windows_os is True:
        configdefaults["RECYCLE_IPS"] = ["OFF", "RECYCLE banlist.txt AFTER A CERTAIN AMOUNT OF TIME - THIS WILL WIPE ALL IP ADDRESSES AND START FROM SCRATCH AFTER A CERTAIN INTERVAL"]
    configdefaults["ARTILLERY_REFRESH"] = ["86370", "RECYCLE INTERVAL AFTER A CERTAIN AMOUNT OF MINUTES IT WILL OVERWRITE THE LOG WITH A BLANK ONE AND ELIMINATE THE IPS - DEFAULT IS 7 DAYS"]
    if is_posix():
        configdefaults["SOURCE_FEEDS"] = ["ON", "PULL ADDITIONAL SOURCE FEEDS FOR BANNED IP LISTS FROM MULTIPLE OTHER SOURCES OTHER THAN ARTILLERY"]
    if is_windows():
        configdefaults["SOURCE_FEEDS"] = ["OFF", "PULL ADDITIONAL SOURCE FEEDS FOR BANNED IP LISTS FROM MULTIPLE OTHER SOURCES OTHER THAN ARTILLERY"]

    keyorder = []
    keyorder.append("MONITOR")
    keyorder.append("MONITOR_FOLDERS")
    keyorder.append("MONITOR_FREQUENCY")
    keyorder.append("SYSTEM_HARDENING")
    keyorder.append("SSH_DEFAULT_PORT_CHECK")
    keyorder.append("EXCLUDE")
    keyorder.append("ENABLE_HONEYPOT")
    keyorder.append("HONEYPOT_BAN")
    keyorder.append("HONEYPOT_BAN_CLASSC")
    keyorder.append("HONEYPOT_BAN_LOG_PREFIX")
    keyorder.append("WHITELIST_IP")
    keyorder.append("TCPPORTS")
    keyorder.append("UDPPORTS")
    keyorder.append("HONEYPOT_AUTOACCEPT")
    keyorder.append("EMAIL_ALERTS")
    keyorder.append("SMTP_USERNAME")
    keyorder.append("SMTP_PASSWORD")
    keyorder.append("2FA_PASS")
    keyorder.append("ENABLE_2FA")
    keyorder.append("ALERT_USER_EMAIL")
    keyorder.append("SMTP_FROM")
    keyorder.append("SMTP_ADDRESS")
    keyorder.append("SMTP_PORT")
    keyorder.append("EMAIL_TIMER")
    keyorder.append("EMAIL_FREQUENCY")
    keyorder.append("SSH_BRUTE_MONITOR")
    keyorder.append("SSH_BRUTE_ATTEMPTS")
    keyorder.append("FTP_BRUTE_MONITOR")
    keyorder.append("FTP_BRUTE_ATTEMPTS")
    keyorder.append("AUTO_UPDATE")
    if is_windows():
        keyorder.append("UPDATE_LOCATION")
        keyorder.append("UPDATE_FREQUENCY")
    keyorder.append("ANTI_DOS")
    keyorder.append("ANTI_DOS_PORTS")
    keyorder.append("ANTI_DOS_THROTTLE_CONNECTIONS")
    keyorder.append("ANTI_DOS_LIMIT_BURST")
    keyorder.append("APACHE_MONITOR")
    keyorder.append("ACCESS_LOG")
    keyorder.append("ERROR_LOG")
    keyorder.append("BIND_INTERFACE")
    keyorder.append("THREAT_INTELLIGENCE_FEED")
    keyorder.append("THREAT_FEED")
    keyorder.append("THREAT_SERVER")
    keyorder.append("THREAT_LOCATION")
    keyorder.append("THREAT_FILE")
    keyorder.append("LOCAL_BANLIST")
    keyorder.append("ROOT_CHECK")
    keyorder.append("SYSLOG_TYPE")
    keyorder.append("LOG_MESSAGE_ALERT")
    keyorder.append("LOG_MESSAGE_BAN")
    keyorder.append("SYSLOG_REMOTE_HOST")
    keyorder.append("SYSLOG_REMOTE_PORT")
    keyorder.append("CONSOLE_LOGGING")
    keyorder.append("RECYCLE_IPS")
    keyorder.append("ARTILLERY_REFRESH")
    keyorder.append("SOURCE_FEEDS")
    for key in configdefaults:
        if key not in keyorder:
            keyorder.append(key)

    # read config file
    createnew = False
    #configpath = get_config_path()
    if os.path.isfile(configfile):
        # read existing config file, update dict
        #print(f"[*] Checking existing config file {configfile}")
        for configkey in configdefaults:
            if config_exists(configkey):
                currentcomment = configdefaults[configkey][1]
                currentvalue = read_config(configkey)
                configdefaults[configkey] = [currentvalue, currentcomment]
            else:
                print(f"[*] Adding new config options {configkey}, default value {configdefaults[configkey][0]}")
    else:
        createnew = True
        #config file does not exist, determine new path

    # write dict to file
    create_config(configfile, configdefaults, keyorder)

    if createnew:
        msg = f"A brand new config file {configfile} was created. Please review the file, change as needed, and launch artillery (again)."
        #print(msg)
        #write_log(msg,1)
#
    return


def create_config(configpath, configdefaults, keyorder) -> None:
    '''builds out config file with some sane defaults
        according to platform and writes it to a file'''
    #configfilepath = configpath
    confile = open(configpath, "w")
    #write_log("[*] Creating/updating config file '%s'" % configpath)
    #write_log("Creating config file %s" % (configpath))
    banner = "#############################################################################################\n"
    banner += "#\n"
    banner += "# This is the Artillery configuration file. Change these variables and flags to change how\n"
    banner += "# this behaves.\n"
    banner += "#\n"
    banner += "# Artillery written by: Dave Kennedy (ReL1K)\n"
    banner += "# Website: https://www.binarydefense.com\n"
    banner += "# Email: info [at] binarydefense.com\n"
    banner += "# Download: git clone https://github.com/binarydefense/artillery artillery/\n"
    banner += "# Install: python setup.py\n"
    banner += "#\n"
    banner += "#############################################################################################\n"
    banner += "#\n"
    confile.write(banner)
    for configkey in keyorder:
        #newline_comment = f"\n# {configdefaults[configkey][1]}\n"
        #newline_config = f"{configkey}=\"{configdefaults[configkey][0]}\"\n"
        newline_comment = "\n# %s\n" % configdefaults[configkey][1]
        newline_config = "%s=\"%s\"\n" % (configkey, configdefaults[configkey][0])
        confile.write(newline_comment)
        confile.write(newline_config)
    confile.close()
    #print(f"[*] Config file created {configpath}")
    return
######################################variable creation section################################################

#is_windows_os = is_windows()
#is_posix_os = is_posix()
####################################Main settings config##########################################


if is_windows_os is True:
    ProgramFolder = os.environ["PROGRAMFILES(X86)"]
    appname = "Artillery"
    apppath = PureWindowsPath(ProgramFolder + "\\" + appname)
    appfile = PureWindowsPath(apppath, "artillery.exe")
    configfile = PureWindowsPath(apppath, "config")
    banlist = PureWindowsPath(apppath, "banlist.txt")
    localbanlist = PureWindowsPath(apppath, "localbanlist.txt")
    win_src = PureWindowsPath(apppath, "src\\windows")
    eventdll = PureWindowsPath(win_src, "ArtilleryEvents.dll")
    logpath = PureWindowsPath(apppath, "logs")
    alertlog = PureWindowsPath(logpath, "alerts.log")
    exceptionlog = PureWindowsPath(logpath, "exceptions.log")
    pidfile = PureWindowsPath(apppath, "pid.txt")
    batchfile = PureWindowsPath(apppath, "artillery_start.bat")
    iconpath = PureWindowsPath(apppath, "src\\icons")
    database = PureWindowsPath(apppath, "database\\temp.database")
    hostname = socket.gethostname()
#HostOs = ""
#SysPath = ""
#
if is_posix_os is True:
    ProgramFolder = "/var/artillery"
    appname = "Artillery"
    apppath = PurePosixPath(ProgramFolder)
    appfile = PurePosixPath(apppath, "Artillery.py")
    configfile = PurePosixPath(apppath, "config")
    banlist = PurePosixPath(apppath, "banlist.txt")
    localbanlist = PurePosixPath(apppath, "localbanlist.txt")
    database = PurePosixPath(apppath, "database/temp.database")
    logpath = PurePosixPath(apppath, "logs")
    alertlog = PurePosixPath(logpath, "alerts.log")
    exceptionlog = PurePosixPath(logpath, "exceptions.log")
    hostname = socket.gethostname()
####################################Email Configs#################################################

two_factor_pass = read_config("2FA_PASS")
two_fa_enabled = is_config_enabled("ENABLE_2FA")
mail_time = read_config("EMAIL_FREQUENCY")
check_interval = int(mail_time)
timer_enabled = is_config_enabled('EMAIL_TIMER')
email_enabled = is_config_enabled("EMAIL_ALERTS")
alert_user = read_config("ALERT_USER_EMAIL")
smtp_user = read_config("SMTP_USERNAME")
smtp_pwd = read_config("SMTP_PASSWORD")
smtp_address = read_config("SMTP_ADDRESS")
smtp_port = read_config("SMTP_PORT")
smtp_from = read_config("SMTP_FROM")
####################################Logging Configs###############################################
syslog_type = read_config("SYSLOG_TYPE")
syslog_remote_host = read_config("SYSLOG_REMOTE_HOST")
syslog_remote_port = read_config("SYSLOG_REMOTE_PORT")
console_logging_enabled = is_config_enabled("CONSOLE_LOGGING")
log_message_alert = read_config("LOG_MESSAGE_ALERT")
log_message_ban = read_config("LOG_MESSAGE_BAN")
recycle_ips_enabled = is_config_enabled("RECYCLE_IPS")
artillery_refresh = read_config("ARTILLERY_REFRESH")
###################################Honeypot Configs###############################################
honeypot_enabled = is_config_enabled("ENABLE_HONEYPOT")
honeypot_ban_enabled = read_config("HONEYPOT_BAN")
ban_class_c = is_config_enabled("HONEYPOT_BAN_CLASSC")
ban_log_prefix = read_config("HONEYPOT_BAN_LOG_PREFIX")
whitelist_ip = read_config("WHITELIST_IP")
tcp_ports = read_config("TCPPORTS")
udp_ports = read_config("UDPPORTS")
honeypot_autoaccept = is_config_enabled("HONEYPOT_AUTOACCEPT")
bind_interface = read_config("BIND_INTERFACE")
#########################################FTP Configs##############################################
ftp_brute_monitor_enabled = is_config_enabled("FTP_BRUTE_MONITOR")
ftp_brute_attempts = read_config("FTP_BRUTE_ATTEMPTS")
#########################################SSH Configs##############################################
ssh_root_check_enabled = is_config_enabled("ROOT_CHECK")
ssh_default_port_check_enabled = is_config_enabled("SSH_DEFAULT_PORT_CHECK")
ssh_brute_monitor_enabled = is_config_enabled("SSH_BRUTE_MONITOR")
ssh_brute_attempts = read_config("SSH_BRUTE_ATTEMPTS")
#########################################Apache Configs###########################################
apache_monitor_enabled = is_config_enabled("APACHE_MONITOR")
access_log_path = read_config("ACCESS_LOG")
error_log_path = read_config("ERROR_LOG")
#########################################File Monitor Configs#####################################
harden_check = is_config_enabled("SYSTEM_HARDENING")
file_monitor_enabled = is_config_enabled("MONITOR")
monitor_folders = read_config("MONITOR_FOLDERS")
monitor_frequency = read_config("MONITOR_FREQUENCY")
exclude_folders = read_config("EXCLUDE")
###########################################Update Configs#########################################
auto_update_enabled = is_config_enabled("AUTO_UPDATE")
#update_location
#update_frequency
###########################################Anti-Dos Configs#######################################
anti_dos_enabled = is_config_enabled("ANTI_DOS")
anti_dos_ports = read_config("ANTI_DOS_PORTS")
anti_dos_throttle_connections = read_config("ANTI_DOS_THROTTLE_CONNECTIONS")
anti_dos_burst_limit = read_config("ANTI_DOS_LIMIT_BURST")
###########################################ThreatFeed Configs#####################################
threat_feed_enabled = is_config_enabled("THREAT_INTELLIGENCE_FEED")
threat_feed = read_config("THREAT_FEED")
threat_server_enabled = is_config_enabled("THREAT_SERVER")
threat_server_location = read_config("THREAT_LOCATION")
threat_file = read_config("THREAT_FILE")
source_feeds_enabled = is_config_enabled("SOURCE_FEEDS")
