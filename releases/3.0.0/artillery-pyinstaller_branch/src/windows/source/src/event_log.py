"""
Script for use with Artillery from BinaryDefense it uses pywin32 api to send messages to eventlog on
windows systems. dll used is custom built for artillery
"""
#This file handles windows eventing using toast notifications and also a custom event dll for artillery.
#writes events to the event log
#

from pathlib import PureWindowsPath
import os
import sys
import time
from win32evtlogutil import ReportEvent, SafeFormatMessage
from win32api import GetCurrentProcess
from win32security import GetTokenInformation, TokenUser, OpenProcessToken
from win32con import TOKEN_READ
import win32evtlog
from win10toast import ToastNotifier
from . import globals
from .core import is_windows, is_posix, init_globals

#
init_globals()
#set some constants that we will use
mymsgDLL = globals.g_eventdll
#AppName = globals.g_appname
data = "Application\0Data".encode("ascii")
#category is always one for now
#and even though its declared as type(int)
#i have to define as int() in reporting func() or it fails

category = int(1)
process = GetCurrentProcess()
token = OpenProcessToken(process, TOKEN_READ)
my_sid = GetTokenInformation(token, TokenUser)[0]
info = win32evtlog.EVENTLOG_INFORMATION_TYPE
warning = win32evtlog.EVENTLOG_WARNING_TYPE
err = win32evtlog.EVENTLOG_ERROR_TYPE


class ToastMessages(ToastNotifier):
    '''Inherits from main Class to add functions.Enables toast\balloon tips on windows 7/8/10 , 08/12/16'''
    def __init__(self):
        super().__init__()
        pass

    def grab_event_info(self):
        #print('hey')
        pass

    def on_event(self):
        self.grab_event_info()

    #
    def get_icon_path(self):
        '''override default icon with custom one. we pass this to showtoast as a path object'''
        #setup blank icon
        new_icon = ''
        #change to icon dir
        os.chdir("src\icons")
        #set home path for directory
        homedir = os.getcwd()
        icon = 'toast_events_icon.ico'
        #create path object to pass
        icondir = PureWindowsPath(homedir, icon)
        if os.path.isfile(icon):
            new_icon = icondir
        else:
            #else fall back and use default of class
            new_icon = None
        return new_icon


toast = ToastMessages()


toast_title = str("Artillery - Advanced Threat Detection")


def write_windows_eventlog(AppName: str, eventID: int, event_type: str, send_toast: bool, ip: None):
    """
    Writes an event to windows event log. also if send_toast is set to True
    will alert user with a toast alert with info concerning attack.

    values:
        - AppName = name of app in windows eventlog
        - eventid = eventid to use
        - event_type = type of alert to use
        - send_toast = send toast alert or not. values accepted TRUE FALSE
        - ip = used for toast alerts if enabled can be None

    event types:
        possible event types are.

        - "win32evtlog.EVENTLOG_INFORMATION_TYPE"
        -  "win32evtlog.EVENTLOG_WARNING_TYPE"
        -  "win32evtlog.EVENTLOG_ERROR_TYPE"


    messages:
        all mesages are stored in dll. possible entries for func are as follows
        Future events are planned. for now the msg's are hard coded
        -    Event,                  eventid,           type
        - ######################################################
        - ARTILLERY_START            100              info
        - ARTILLERY_STOP             101              info
        - HONEYPOT_ATTACK            200              warning
        - Smb_Client_Enabled         300              warning
        - Smb_Server_Enabled         301              warning
        - WPAD_Running               302              warning
        - LLMNR_Key_Not_Present      303              warning
        - Smb_Disable_Help           310              info
        - DLL_Installed              500              info
        - Dll_Removed                501              info
        - Artillery_Installed        502              info
        - Artillery_Removed          503              info

    for ex.

        - write_windows_eventlog('Artillery', 200, warning, True, ip)

        This will log a honeypot attack message and send toast alert with values given


    Calls ReportEvent() from pywin32.

        - ReportEvent(AppName, eventID, eventCategory=int(category), eventType=event_type, data=data, sid=my_sid)


    """
    if send_toast is True:
        if eventID == 200:
            attacking_ip = str(ip)
            toast.show_toast(title=toast_title,
            msg=f"I've detected an atack from {str(attacking_ip)}" + "\n""an event was sent to the Application eventlog",
            icon_path=None,
            duration=2,
            threaded=False,
            callback_on_click=None
            )
        elif eventID == 100:
            toast.show_toast(title=toast_title,
            msg="Artillery has been started",
            icon_path=toast.get_icon_path(),
            duration=2,
            threaded=False,
            callback_on_click=toast.on_event()
            )
        else:
            pass

    ReportEvent(AppName, eventID, eventCategory=category, eventType=event_type, data=data, sid=my_sid)
#


def read_windows_eventlog(LogName: str, eventID: int, event_type: str):
    pass
