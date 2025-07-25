'''docstring todo'''
# -*- coding: utf-8 -*-
#
#  Events.py
#
#  Copyright 2018 Russ Haun
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#
#This file handles windows eventing using toast notifications and also a custom event dll for artillery.
#the dll writes events to the event log
#
from pathlib import PureWindowsPath
import os
import sys
import time
from win32evtlogutil import ReportEvent, AddSourceToRegistry, RemoveSourceFromRegistry, SafeFormatMessage
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
AppName = globals.g_appname
data = "Application\0Data".encode("ascii")
#category is always one for now
#and even though its declared as type(int)
#i have to define as int() in reporting func() or it fails

category = 1
process = GetCurrentProcess()
token = OpenProcessToken(process, TOKEN_READ)
my_sid = GetTokenInformation(token, TokenUser)[0]
info = win32evtlog.EVENTLOG_INFORMATION_TYPE
warning = win32evtlog.EVENTLOG_WARNING_TYPE
err = win32evtlog.EVENTLOG_ERROR_TYPE
def write_windows_eventlog(appname: str, eventid: int, eventtype: str, send_toast: bool):
    if send_toast is True:
        print("sending toast...")
    else:
        pass

#Left this here for reference
#"""Report an event for a previously added event source."""
#ReportEvent(appName, eventID, eventCategory = 0, eventType=win32evtlog.EVENTLOG_ERROR_TYPE, strings = None, data = None, sid=None):


class ToastMessages(ToastNotifier):
    '''Inherits from main Class to add functions.Enables toast\balloon tips on windows 7/8/10 , 08/12/16'''
    def __init__(self):
        super().__init__()
        pass
    #
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
        icondir = PureWindowsPath(homedir,icon)
        if os.path.isfile(icon):
            new_icon = icondir
        else:
            #else fall back and use default of class
            new_icon = None
        return new_icon
#set up Toast class
toast = ToastMessages()
#below are as defined in the "dll" look @ included .mc file for message contents
#descr = 'ARTILLERY_START'
def ArtilleryStartEvent():
        toast.show_toast(title="Artillery - Advanced Threat Detection",
                   msg="Artillery has been started",
                   icon_path= None,
                   duration=2,
                   threaded=False,
                   callback_on_click=toast.on_event()
                   )
        eventID = 100
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=info, data=data, sid=my_sid)
#
#descr = 'ARTILLERY_STOP'
def ArtilleryStopEvent():
        eventID = 101
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=info, data=data, sid=my_sid)
#
#descr = 'HONEYPOT_ATTACK'
def HoneyPotEvent(ip):
        toast.show_toast(title="Artillery",
                   msg="I've detected an atack from "+str(ip)+"\n""an event was sent to the eventlog",
                   icon_path=None,
                   duration=2,
                   threaded=True,
                   callback_on_click=None
                   )
        ipparts = ip.split(".")
        c_ip = "%s.%s.%s.%s" % (ipparts[0], ipparts[1], ipparts[2], ipparts[3])
        eventID = 200
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=warning, strings=c_ip, data=data, sid=my_sid)
#
#descr = 'Smb_Client_Enabled'
def SmbClientEnabled():
        eventID = 300
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=warning, data=data, sid=my_sid)
#
#descr = 'Smb_Server_Enabled'
def SmbServerEnabled():
        eventID = 301
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=warning, data=data, sid=my_sid)
#
#desrc = 'WPAD_Running'
def WpadEnabled():
        eventID = 302
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=warning, data=data, sid=my_sid)
#
#descr = 'LLMNR_Key_Not_Present'
def LLMNREnabled():
        eventID = 303
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=warning, data=data, sid=my_sid)
#
#descr ='Smb_Disable_Help'
def SmbHelp():
        eventID = 310
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=info, data=data, sid=my_sid)
#
#desrc = 'Dll_Installed'
def DllInstalled():
        eventID=500
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=info, data=data, sid=my_sid)
#
#descr = 'Dll_Removed'
def DllRemoved():
        eventID=501
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=info, data=data, sid=my_sid)
#
#descr = 'Artillery_Installed'
def ArtilleryInstalled():
        eventID=502
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=info, data=data, sid=my_sid)
#
#desrc = 'Artillery_Uninstalled'
def ArtilleyRemoved():
        eventID=503
        ReportEvent(AppName, eventID, eventCategory=int(category), eventType=info, data=data, sid=my_sid)
#


