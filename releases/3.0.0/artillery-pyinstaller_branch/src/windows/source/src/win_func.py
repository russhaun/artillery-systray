
# -*- coding: utf-8 -*-
#
#
"""
 File contains functions for use in Artillery from BinaryDefense specific to windows.
"""
#
from re import U
import subprocess
import re
import os
import sys
import time
from win32evtlogutil import RemoveSourceFromRegistry
from win32api import SetConsoleTitle, GetCurrentProcessId
from win32security import GetTokenInformation, TokenUser, OpenProcessToken
import win32file
import win32con
from .event_log import write_windows_eventlog , err , warning, info
from . import globals
from .core import write_log, write_console, is_windows, is_posix, init_globals
from src.config import read_config
import requests
#import random
import platform
#
init_globals()
#
if is_windows():

    from winreg import *
#
if is_posix():
    print("[!] Linux detected!!!!!!!!!.This script wil only run on windows. please try again")
    sys.exit()
#
#
####################################################################################
#Function to return lists for most functions in this file
#that way all there is to change is this function. this will insert all info
#into list to use for referencing different things throught file
#
def get_config(cfg):
    '''get various pre-set config options used throughout script'''
    #Current artillery version
    current = ['2.9.1']
    #Known Os versions
    oslst = ['Windows 7 Pro', 'Windows Server 2008 R2 Standard', 'Windows 8.1 Pro', 'Windows 10 Pro', 'Windows Small Business Server 2011 Essentials',
             'Windows Server 2012 R2 Essentials', 'Hyper-V Server 2012 R2','Windows Server 2016 Standard', 'Windows Server 2016 Essentials']
    #Known Build numbers
    builds = ['7601', '9600', '1709', '17134', '18362', '19041', '19042','19043','14393','19044','19045']
    regkeys = [r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', r'SYSTEM\CurrentControlSet\Services\LanmanServer', r'SYSTEM\CurrentControlSet\Services\LanmanWorkstation',
               r'SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc',
               r'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient']
    #switches for New-NetFirewallRule & Set-NetFirewallRule & Remove-NetFirewallRule functions in
    #powershell used to initially create group and then add to it/remove from
    firew = ['New-NetFirewallRule ', 'Set-NetFirewallrule ', 'Remove-NetFirewallRule', '-Action ', '-DisplayName ', '-Direction ', '-Description ', '-Enabled ', '-RemoteAddress']
    pshell = ['powershell.exe ', '-ExecutionPolicy ', 'Bypass ']
    #list to hold variables of host system tried to grab most important ones
    path_vars = ['SYSTEMDRIVE','PROGRAMFILES','COMPUTERNAME', 'PROCESSOR_ARCHITECTURE','PSMODULEPATH','NUMBER_OF_PROCESSORS','WINDIR']
    #temp list
    temp = []
    if cfg == 'CurrentBuild':
        return current
    elif cfg == 'OsList':
        return oslst
    elif cfg == 'Builds':
        return builds
    elif cfg == 'Reg':
        return regkeys
    elif cfg == 'Temp':
        return temp
    elif cfg == 'Firewall':
        firew.sort(reverse=True)
        return firew
    elif cfg == 'PShell':
        pshell.sort(reverse=True)
        return pshell
    elif cfg == 'Path':
        return path_vars
    else:
        pass
def get_title() -> None:
    '''sets title of window on windows systems using pywin32.winapi'''
    SetConsoleTitle('Artillery - Advanced Threat Detection')
    return
#
def get_pid() -> None:
    """
    grabs current processid using GetCurrentProcessId()
    from pywin32.winapi and saves to txt file. for future use with "restart_server" script
    """
    p_id = GetCurrentProcessId()
    s_id = str(p_id)
    pid_txt = globals.g_pidfile
    with open(pid_txt, 'w') as cpid:
        cpid.write(s_id + "\n")
        cpid.close()
    write_log(f"[*] Current ProcessId: {s_id}")
    return
#Artillery version info
####################################################################################
def current_version() -> None:
    '''returns current windows release of artillery'''
    get_ver = get_config('CurrentBuild')
    ver = get_ver[0]
    s_ver =str(ver)
    info = f"[*] Artillery Ver: {s_ver}"
    write_log(info)
    write_console(info)
    return


#OS functions
####################################################################################
#
def get_path_info():
    """grabs current host path info and returns needed values for functions in script
     with the help of a provided list of items to look for. currently returns
     windows drive, systemdrive ,programfiles(x86) , architecture, computername
     """
    pathcfg = []
    lines = []
    keywords = get_config('Path')
    exp = re.compile("|".join(keywords), re.I)
    for line in os.environ:
        line = line.strip()
        lines.append(line)
        if re.findall(exp, line):
            line = line.strip()
            pathcfg.append(line)
    # sort all the lists i did reverse here for 2 reasons. without reverse true it
    # did not sort same order with default method of just plain .sort()
    # 2 tried reverse false had no effect.
    keywords.sort(reverse=True)
    lines.sort()
    pathcfg.sort(reverse=True)
    #this setion is used for testing only used when adding new variables
    ################################################################################
    def keyword_list():
        print("*********************lines from keyword list**********************")
        for item in keywords:
            print(item)
    def retrieved_items():
        print("*********************lines from created path list******************")
        for item in pathcfg:
            print(item)
    def avail_items():
        print("*********************availible items from host list****************")
        for item in lines:
            print(item)
    ##################################################################################
    dv = "default_value"
    #these take retrived path vars and resolve to true value
    windrive = os.environ.get(pathcfg[0], dv)
    sysdrive = os.environ.get(pathcfg[1], dv)
    programfiles = os.environ.get(pathcfg[3], dv)
    arch = os.environ.get(pathcfg[5], dv)
    compname = os.environ.get(pathcfg[7], dv)
    #avail_items()
    return(sysdrive,windrive,programfiles,arch,compname)
#
#
def freeze_check() -> str:
    '''check to see if we are runnning in a frozen executable or from the .py file. ex. pyinstaller'''
    frozen = 'not running'
    # if we are running in a bundle
    if getattr(sys, 'frozen', False):
        frozen = 'running'
        bundle_dir = sys._MEIPASS
        temp = 'cold'
    else:
        # if we are running in a normal Python environment
        bundle_dir = os.path.dirname(os.path.abspath(__file__))
        temp = 'hot'
    if temp == 'cold':
        exe_path = os.path.dirname(sys.executable)
        mei_path = bundle_dir
        write_log(f"[*] Freeze Check: we are {frozen} frozen.")
        py_ver = platform.python_version()
        #write_console(f"[*] Python ver: {py_ver}")
        write_log(f"[*] Python ver: {py_ver}")
        return str(exe_path)
    else:
        py_ver = platform.python_version()
        write_log(f"[*] Freeze Check: we are {frozen} frozen.")
        write_log(f"[*] Python ver: {py_ver}")


#
def get_update_info():
    '''grabs user info when u start script. used mainly for update locations when
    starting as an standard user i have to create some stuff first
    for main_update func to complete properly'''
    paths = get_path_info()
    tmp = paths[0]+ "\\temp"
    h_path = os.environ['HOMEPATH']
    update_path = h_path +"\\downloads\\ArtilleryUpdates"
    settings = tmp + "\\UpdateSettings.txt"
    if not os.path.isdir(update_path):
        os.makedirs(update_path)
    if not os.path.isfile(settings):
        #print("[*] No settings file found.....")
        os.makedirs(tmp)
    with open(settings, 'w') as settingsfile:
        settingsfile.write(update_path)
    settingsfile.close()
#
def update_windows():
    '''Update routine for Artillery on windows systems. Uses Requests along with Zipfile
    to reach out and download&extract updates from github if any after checking upstream.'''
    #
    write_console("[*] Checking for updates.....")
    hv = get_os()
    path_to_updates = read_config("UPDATE_LOCATION")
    print("[*] Current update path settings: " + str(path_to_updates))
    update_loc = []
    paths = get_path_info()
    tmp = paths[0]+ "\\temp"
    #file created on artillery start
    update_settings = tmp +"\\UpdateSettings.txt"
    #check to see if file exists first possibly using admin acct as logged on user.
    #the file never gets created this way so it might error out.
    # I use "users\%username%\downloads\artilleryupdates as update_path value"
    if not os.path.isfile(update_settings):
        get_update_info()
        time.sleep(1)
        with open(update_settings, 'r')as us:
            for line in us:
                line = line.strip()
                update_loc.append(line)
    else:
        with open(update_settings, 'r')as us:
            for line in us:
                line = line.strip()
                update_loc.append(line)
    #
    update_path = update_loc[0]
   #change to update dir
    os.chdir(update_path)
    #only launch if files are present
    if os.path.isfile('start_update.bat'):
        os.system("start cmd /K start_update.bat")
    else:
        #download what we dont have and then launch
        write_console("[*] Downloading needed files to get updates")
        write_console("[*] Downloading update.py")
        f_name = 'update.py'
        url = 'https://raw.githubusercontent.com/russhaun/Updates/master/Artillery/update.py'
        r = requests.get(url)
        with open(f_name , 'w') as ufile:
            #response is binary have to convert it to utf-8
            response = r.content
            decoded = response.decode(encoding="utf-8")
            ufile.write(decoded)
        ufile.close()
        write_console("[*] Done with Update.py")
        write_console("[*] Downloading start_update.bat")
        #download batch file
        f_name = 'start_update.bat'
        url = 'https://raw.githubusercontent.com/russhaun/Updates/master/Artillery/start_update.bat'
        r = requests.get(url)
        with open(f_name , 'w') as bfile:
            #response is binary have to convert it to utf-8
            response = r.content
            decoded = response.decode(encoding="utf-8")
            bfile.write(decoded)
        bfile.close()
        write_console("[*] Done with start_update.bat")
        write_console("[*] Starting update.....")
        time.sleep(5)
        os.system("start cmd /K start_update.bat")

        #pass
    #
def get_os()-> None:
    '''This function uses pre-compiled lists to try and determine host os by comparing values to host entries
    if a match is found reports version'''
    if is_posix:
        pass
    if is_windows:
        OsName = "Unknown version"
        OsBuild = "Unknown build"
        #reg key list
        reg = get_config('Reg')
        #known os list
        kvl = get_config('OsList')
        #known builds
        b1 = get_config('Builds')
        #final client cfg list
        ccfg = []
        try:
            oskey = reg[0]
            oskeyctr = 0
            oskeyval = OpenKey(HKEY_LOCAL_MACHINE, oskey)
            while True:
                ossubkey = EnumValue(oskeyval, oskeyctr)
                #dumps all results to txt file to parse for needed strings below
                osresults = open("version_check.txt", "a")
                osresults.write(str(ossubkey)+'\n')
                oskeyctr += 1
        #catch the error when it hits end of the key
        except WindowsError:
            osresults.close()
            #open up file and read what we got
            data = open('version_check.txt', 'r')
            # keywords from registry key in file
            keywords = ['ProductName', 'CurrentVersion', 'CurrentBuildNumber']
            exp = re.compile("|".join(keywords), re.I)
            for line in data:
                #write out final info wanted to list
                if re.findall(exp, line):
                    line = line.strip()
                    ccfg.append(line)
            data.close()
            #delete the version info file. we dont need it any more
            subprocess.call(['cmd', '/C', 'del', 'version_check.txt'])
            # now compare 3 lists from get_config function and client_config.txt to use for id
            #sort clientconfig list to have items in same spot accross platforms
            ccfg.sort(reverse=True)
            osresults = ccfg[0]
            #print("[*] OS results: "+ osresults)
            buildresults = ccfg[2]
            #print("[*] Build results: "+buildresults)
            for name in kvl:
                if name in osresults:
                    OsName = name
            for build in b1:
                if build in buildresults:
                    OsBuild = build
            #when were done comparing print what was found
            write_console("[*] Detected OS: " + OsName+ " Build: " + OsBuild)
        return
#
#
def get_win_config(param):
    '''Returns a value from windows registry related to settings for artillery.'''
    ccfg = []
    results = []
    try:
        oskey = r'SOFTWARE\Artillery\Settings'
        oskeyctr = 0
        oskeyval = OpenKey(HKEY_LOCAL_MACHINE, oskey)
        while True:
            ossubkey = EnumValue(oskeyval, oskeyctr)
            #appends all items to new list to find our option
            results.append(ossubkey)
            oskeyctr += 1
        #catch the error when it hits end of the key
    except WindowsError:
        #look @ our results and return option
        data = results
        #print("[*] current param: "+ str(param))
        keywords = [param]
        exp = re.compile("|".join(keywords), re.I)
        for item in data:
            if re.findall(exp, str(item)):
                #print("found item: "+str(item))
                ccfg.append(item)
    #clear the results list
    results.clear()
    #setup our tuple to query
    try:
        value = ccfg[0]
    except IndexError as e:
        print("failed @ "+str(keywords))
    #grab the actual value
    setting =value[1]
    #remove any qoutes
    clean = setting.replace('"', "")
    #return string value found
    return clean
        #osresults.close()
#service functions
####################################################################################
def insecure_service_check():
    """
        Performs checks on windows systems to see if known vulnerable services are enabled
    and alerts if found. llmnr,wpad,smbv1. this func still needs alot of work to be effective
    at properly detecting status of components.uses the registry heavily

    Note:

            This whole routine wil be replaced at some point. i am devoloping script with
        funtions to handle registry exclusivly with no txt files. 90% finished

    """
    #warning = ""
    #
    if is_windows():
        #loglink prints the full url to copy and paste
        #printlink is what is printed to screen
        srvlog = '[*] Service Check: SMBv1 was detected!!!. Please refer to this link and follow instructions.\n https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and'
        srvprint = '[*] Service Check: Please refer to alerts.log for more information on steps to take'
        srvwarning = '[*] Service Check: SMBv1 Server is enabled!!!. Unless absolutly neccessary please disable.\n'
        srvdisabled = '[*] Service Check: SMBv1 Server is disabled'
        #SMBv1 server check. there are 2 more keys for now i just read one of them WIP
        try:
            srvkey = r'SYSTEM\CurrentControlSet\Services\LanmanServer'
            srvkeyctr = 0
            srvkeyval = OpenKey(HKEY_LOCAL_MACHINE, srvkey)
            while True:
                #prints out results to txt file to parse for needed strings below
                srvsubkey = EnumValue(srvkeyval, srvkeyctr)
                smbcheck = open("smbsrv_check.txt", "a")
                smbcheck.write(str(srvsubkey))
                srvkeyctr += 1
        #catch the error when it hits end of the key
        except WindowsError:
            smbcheck.close()
            #Now open the file and search the results for values wanted.
            srvdata = open('smbsrv_check.txt', 'r')
            srvresults = srvdata.read()
            #just look for the string Srv2 for now.
            srvmatch = re.findall('Srv2', srvresults)
            if srvmatch:
                write_console(str(srvdisabled))
                write_log(str(srvdisabled))
            else:
                write_windows_eventlog("Artillery", 301, warning, False, None)
                write_console(str(srvwarning) + str(srvprint))
                write_log(str(srvwarning) + str(srvlog))
        srvdata.close()
        #SMBv1 Clientside component
        #use the strings from above because why not
        cliprint = srvprint
        clilog = srvlog
        cliwarning = '[*] Service Check: SMBv1 Client is enabled!!!. Unless absolutly neccessary please disable.\n'
        clidisabled = '[*] Service Check: SMBv1 Client is disabled'
        try:
            cli = 0
            CliKey = r'SYSTEM\CurrentControlSet\Services\LanmanWorkstation'
            CliKeyValue = OpenKey(HKEY_LOCAL_MACHINE, CliKey)
            while True:
                clisubkey = EnumValue(CliKeyValue, cli)
                clicheck = open('smbcli_check.txt', 'a')
                clicheck.write(str(clisubkey))
                cli += 1
        except WindowsError:
            clicheck.close()
            clidata = open('smbcli_check.txt', 'r')
            cliresults = clidata.read()
            #just look for the string MRxSmb20 for now.
            climatch = re.findall('MRxSmb20', cliresults)
            if climatch:
                write_console(str(clidisabled))
                write_log(str(clidisabled))
            else:
                write_windows_eventlog("Artillery", 300, warning, False, None)
                write_log(str(cliwarning) + str(clilog))
                write_console(str(cliwarning) + str(cliprint))
        clidata.close()
        #Check for WinHTTP Web Proxy Auto-Discovery Service (wpad) being disabled
        try:
            wpadctr = 0
            wpadsvckey = r'SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc'
            wpadsvcvalue = OpenKey(HKEY_LOCAL_MACHINE, wpadsvckey)
            while True:
                wpadsubkey = EnumValue(wpadsvcvalue, wpadctr)
                wpadcheck = open('wpad_check.txt', 'a')
                wpadcheck.write(str(wpadsubkey))
                wpadctr += 1
        except WindowsError:
            wpadcheck.close()
            #
            wpaddata = open('wpad_check.txt', 'r')
            wpadresults = wpaddata.read()
            #just look for the wpadoverride string for now.
            wpadmatch = re.findall('WpadOverride', wpadresults)
            if wpadmatch:
                write_console("[*] Service Check: WPAD Override key is present")
                write_log("[*] Service Check: WPAD Override key is present")
            else:
                write_windows_eventlog("Artillery", 302, warning, False, None)
                write_console("[*] Service Check: WPAD overide key is not present. you will be vuln to MITM attacks")
                write_log("[*] Service Check: WPAD overide key is not present. you will be vuln to MITM attacks")
        wpaddata.close()
        #
        #check for LLMNR
        try:
            llmnrctr = 0
            llmnrkey = r'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            #added for cases where key is not present
            try:
                llmnrkeyvalue = OpenKey(HKEY_LOCAL_MACHINE, llmnrkey)
            except FileNotFoundError:
                write_console("[*] Service Check: LLMNR key is not present skipping")
                write_log("[*] Service Check: LLMNR key is not present skipping")
                return
            #if we main find key iterate through dumping all values
            while True:
                llmnrsubkey = EnumValue(llmnrkeyvalue, llmnrctr)
                llmnrcheck = open('llmnr_check.txt', 'a')
                llmnrcheck.write(str(llmnrsubkey))
                llmnrctr += 1
        #catch error by default this key is not present which means it is enabled
        except WindowsError:
            llmnrcheck.close()
            llmnrdata = open('llmnr_check.txt', 'r')
            llmnrresults = llmnrdata.read()
            #just look for the multicast string for now.
            llmnrmatch = re.findall('EnableMulticast', llmnrresults)
            if llmnrmatch:
                write_console("[*] Service Check: LLMNR key to disable multicast is present")
                write_log("[*] LLMNR key to disable multicast is present")
            else:
                write_windows_eventlog("Artillery",303, warning, False, None)
                write_console("[*] Service Check: LLMNR key to disable multicast is not present. you might be vuln to MITM attacks")
                write_log("[*] LLMNR key to disable multicast is not present. you might be vuln to MITM attacks")
        llmnrdata.close()
        #remove files that were created to make sure we get consistant results
        #if we don't it will forever append the file and make it bigger.
        #to see what i dump comment these lines to keep files
        path = str(globals.g_apppath)
        if os.path.isfile(path+"\\smbcli_check.txt"):
            subprocess.call(['cmd', '/C', 'del', path+"\\smbcli_check.txt"], shell=True)
            subprocess.call(['cmd', '/C', 'del', path+"\\smbsrv_check.txt"], shell=True)
            subprocess.call(['cmd', '/C', 'del', path+"\\llmnr_check.txt"], shell=True)
            subprocess.call(['cmd', '/C', 'del', path+"\\wpad_check.txt"], shell=True)
#
def watch_directory_for_changes(Fpath,k=None):
    '''this will monitor a folder path of your choosing and notify on
    changes this will only work on Windows systems
   '''
    ACTIONS = {
        1 : "Created",
        2 : "Deleted",
        3 : "Updated",
        4 : "Renamed from something",
        5 : "Renamed to something"
    }
  #
    FILE_LIST_DIRECTORY = 0x0001
  #without FILE_SHARE_DELETE on the CreateFile call, the directory can't be deleted or renamed while it's being watched
  #removing FILE_SHARE_DELETE prevents renaming or deleting ?immutable maybe kinda?
    path_to_watch = Fpath
    hDir = win32file.CreateFile (
    path_to_watch,
    FILE_LIST_DIRECTORY,
    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
    None,
    win32con.OPEN_EXISTING,
    win32con.FILE_FLAG_BACKUP_SEMANTICS,
    None
    )
    while 1:
    #
    # ReadDirectoryChangesW takes a previously-created
    # handle to a directory, a buffer size for results,
    # a flag to indicate whether to watch subtrees and
    # a filter of what changes to notify.
    #
    # up
    # the buffer size to be sure of picking up all
    # events when a large number of files were
    # deleted at once.
    #
        results = win32file.ReadDirectoryChangesW (
        hDir,
        1024,
        True,
        win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
        win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
        win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
        win32con.FILE_NOTIFY_CHANGE_SIZE |
        win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
        win32con.FILE_NOTIFY_CHANGE_SECURITY,
        None,
        None
        )

        for action, file in results:
            full_filename = os.path.join (path_to_watch, file)
            print('[!!] Monitor Alert: ' +full_filename, ACTIONS.get (action, "Unknown"))


##########################################################################
#This section contans all info needed for event dll to operate properly.
# below functions handles all installing, registring of dll, removing of dll
##########################################################################
# functions to remove\install dll on windows hosts.......
#
def InstallDLL():
    def add_reg_entries():
        '''Creates a subkey under the specified key and stores registration information from a specified file into that subkey.'''
        evtlog_key = r'SYSTEM\CurrentControlSet\Services\EventLog\Application'
        sub_key = 'Artillery'
        file_name = r'src\windows\ArtilleryEvents.reg'
        print('[*] Adding Registry entries........')
        LoadKey(HKEY_LOCAL_MACHINE, evtlog_key, sub_key, file_name)
    def copy_dll():
        pass
            #
        #register dll with system
    add_reg_entries()

        #AddSourceToRegistry(appName = AppName, msgDLL = mymsgDLL, eventLogType = "Application", eventLogFlags = None):
#
#
def UninstallDLL():
    """Removes a source of messages from the event log."""
    RemoveSourceFromRegistry(appName = globals.g_appname, eventLogType = "Application")
    print("[*] DLL entries removed from registry")
