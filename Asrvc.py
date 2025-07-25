'''
This file is a class that exposes controls on windows to allow start/stop/restart capablities
to work with the artillery binary. Future plans are in the works also for updates/banning/removing bans.

the goal of it is to mimic windows service control applet without the applet.
'''


import signal
import argparse
import time
import sys
import os
from threading import Thread
import subprocess
import wmi
import win32process
from src.logger.log_handler import file_logger
home = os.getcwd()
logs = file_logger("asvc",f"{home}\\logs\\servicemgr.txt")
#set our output to 1 to not hold anything and just flush it. ex.stderr/stdout
PYTHONUNBUFFERED = 1
PROGRAMDATA = os.environ["PROGRAMDATA"]
PROGRAM_FILES= os.environ["PROGRAMFILES(x86)"]
PROGRAM_PATH = f"{PROGRAM_FILES}\\Artillery"
UPDATE_BINARY_PATH = f"{PROGRAMDATA}\\Artillery\\ArtilleryUpdate.exe"


class SVCMgr():
    def __init__(self):
        self.pid = win32process.GetCurrentProcessId()
        logs.info(f"[*] Artillery Service controller starting with pid: {str(self.pid)}")
    
    def is_service_active(self)->tuple[bool,str,str]:
        '''
        checks to see if process is running already.Returns a tuple of bool,pid,msg
        '''
        wmipid = []
        c = wmi.WMI()
        try:
            logs.info('[*] Checking if service is active.....')
            for process in c.Win32_Process(name="artillery.exe"):
                wmipid.append(process.ProcessId)
        except wmi.WMI_EXCEPTIONS as a:
            pass
        if len(wmipid) == 0:
            pid = "0"
            msg = "[*] Service is not active."
            logs.info(msg)
            return (False,pid,msg)
        else:
            pid = wmipid[0]
            msg = f"[*] Service is active with pid of: {str(pid)}"
            logs.info(msg)
            return (True,pid,msg)

    def start(self):
        """
        Starts artillery binary
        """
        logs.info('[*] Trying to start Artillery now.')
        #check to see if we are already running if so
        #exit and do not try to start a new instance
        is_runninig = self.is_service_active()
        service_running = is_runninig[0]
        service_msg = is_runninig[2]
        if service_running is True:
            logs.info("[*] Service is already running. Nothing to do")
            sys.exit()
        else:
            #try to start the service and verify it is running
            logs.info(service_msg)
            try:
                executable = f"{PROGRAM_PATH}\\Artillery.exe"
                proc = subprocess.run(args=executable,creationflags=subprocess.CREATE_NO_WINDOW,start_new_session=False,timeout=5)
            except subprocess.TimeoutExpired as a:
                #pass on time out we are aware
                pass
            finally:
                #5 secs is more then enough 
                #time to wait to verify it started
                service_check = self.is_service_active()
                service_running = service_check[0]
                service_pid = service_check[1]
                service_msg = service_check[2]
                if service_pid == "0":
                    logs.info("[*] Service did not start")
                    return "[*] Service did not start"
                else:
                    logs.info(service_msg)
                    return service_msg
        
    def stop(self):
        '''
        stops main exe by using os.kill()
        '''
        print("[*] Attempting to stop service")
        logs.info("[*] Attempting to stop service")
        service_status = self.is_service_active()
        service_running = service_status[0]
        service_pid = str(service_status[1])
        service_msg = str(service_status[2])
        #check to see if service is running if false just quit
        if service_running is False:
            print(service_msg)
            sys.exit()
        else:
            print(service_msg)
            try:
                msg = f"[*] Killing Artillery with processID of: {service_pid}"
                logs.info(msg)
                try:
                    #works no errors but still not clean find a better way?
                    os.kill(int(service_pid),signal.SIGTERM)
                except SystemError as e:
                    logs.critical(e.with_traceback(None))
            except subprocess.CompletedProcess as err:
                logs.info("Stopping")
                time.sleep(5)
                sys.exit()
            except WindowsError as werr:
                logs.critical(werr)
                sys.exit()
    
    def status(self):
        '''
        Checks to see if service is running
        '''
        is_active = self.is_service_active()
        active = is_active[0]
        active_pid = str(is_active[1])
        active_msg = str(is_active[2])
        if active is True:
            logs.info(active_msg)
            time.sleep(2)
            sys.exit()
        else:
            logs.info(active_msg)
            time.sleep(2)
            sys.exit()
    
    def update(self):
        """
        calls update binary when updates are detected.
        """
        return "Not implemented yet"

    def remove_ban(self):
        """
        removes an ip from routing table and banlist
        """
        return "Not implemented yet"

    def add_ban(self):
        """
        adds an ip to the routing table and banlist
        """
        return "Not implemented yet"

if __name__ == "__main__":
    #setup our parser to accept cmd line options.
    #for now it is basic more options wil be added over time.
    #import our class object
    service = SVCMgr()
    parser = argparse.ArgumentParser(add_help=True)
    subparser = parser.add_subparsers()
    start_parser = subparser.add_parser(name='start', help='starts with default settings.')
    start_parser.add_argument('start', action='store_true')
    start_parser.set_defaults(function=service.start)
    stop_parser = subparser.add_parser(name='stop', help='stops when run as a service.')
    stop_parser.add_argument("stop", action='store_true')
    stop_parser.set_defaults(function=service.stop)
    status_parser = subparser.add_parser(name='status', help='returns status when run as a service')
    status_parser.add_argument("status", action='store_true')
    status_parser.set_defaults(function=service.status)
    update_parser = subparser.add_parser(name='update', help='Updates software (Systray & Artillery)')
    update_parser.add_argument('update', action='store_true')
    update_parser.set_defaults(function=service.update)
    unban_parser = subparser.add_parser(name='unban', help='removes an ip from banlist and routing table')
    unban_parser.add_argument('unban', action='store_true')
    unban_parser.set_defaults(function=service.remove_ban)
    ban_parser = subparser.add_parser(name='ban', help='adds an ip to the banlist and routing table')
    ban_parser.add_argument('ban', action='store_true')
    ban_parser.set_defaults(function=service.add_ban)
    args = parser.parse_args()
    

    try: #running the function supplied
        args.function()
    except AttributeError:
        #if error print help
        parser.print_help()
        #sys.exit()