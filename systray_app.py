"""
    Systray app for use with Artillery binary.
Gives access to logs,settings,restarting service and updates
for main Artillery app 


    todo:

        listen for alerts from main service process and presents to user as toasts notifications using windows

"""
#from pathlib import PureWindowsPath
import ctypes
import subprocess
import requests
import socketserver
import threading
import os
import re
import time
import sys
import wx
import wx.xml
import traceback
import wx.richtext
import string
from wx.adv import AboutDialogInfo, AboutBox, TaskBarIcon
import webbrowser
from src.config.systray_defaults import CURRENT_SETTINGS, GLOBAL_SETTINGS
from src.logger.log_handler import file_logger
updatelogs = GLOBAL_SETTINGS.get("UPDATE_LOG_FILE")[0]
traylogs = GLOBAL_SETTINGS.get("SYSTRAY_LOG_FILE")[0]
client_ver = CURRENT_SETTINGS.get("ARTILLERY_VER")[0]
logpath = GLOBAL_SETTINGS.get("ARTILLERY_LOG_FILE")[0]
settings_app = GLOBAL_SETTINGS.get("SETTINGS_APP")[0]
service_app = GLOBAL_SETTINGS.get("SERVICE_MGR")[0]
update_app = GLOBAL_SETTINGS.get("UPDATE_APP")[0]
logs = file_logger("systray app", traylogs)
have_alerts = False
incoming_alerts =""


class SysTrayApp(TaskBarIcon):
    '''
    creates a systray app for use in the systemtray.
    '''
    def __init__(self, frame):
        TaskBarIcon.__init__(self)
        #define our main frame to use the controls availible in it
        #reduces code reuse
        self.frame = frame
        logs.info("Tray app starting")
        self.SetIcon(wx.Icon('.//src//icons//tray_icon.png', wx.BITMAP_TYPE_PNG), 'Artillery systray')
        self.Bind(wx.EVT_MENU, self.frame.on_open_settings, id=1)
        self.Bind(wx.EVT_MENU, self.frame.on_view_log_file, id=2)
        self.Bind(wx.EVT_MENU, self.frame.on_check_for_updates, id=3)
        self.Bind(wx.EVT_MENU, self.frame.on_restart_service, id=4)
        self.Bind(wx.EVT_MENU, self.on_taskbar_close, id=5)
        self.Bind(wx.EVT_MENU, self.frame.on_view_updates_log_file, id=6)
        self.Bind(wx.EVT_MENU, self.frame.on_view_systray_log_file, id=7)
        self.Bind(wx.EVT_MENU, self.frame.on_add_banlist_entry, id=11)
        self.Bind(wx.EVT_MENU, self.frame.on_remove_banlist_entry, id=12)
        #.Bind(wx.EVT_MENU, self.frame.OnTaskBarActivate, id=15)
        self.Bind(wx.EVT_MENU, self.frame.on_start_service, id=9)
        self.Bind(wx.EVT_MENU, self.frame.on_stop_service, id=8)
        self.ShowBalloon("Artillery Tray","Starting.......")
        self.start_alert_listener()

    def CreatePopupMenu(self):
        """
        creates popup menu and returns it
        """
        #base Menu for popup
        menu = wx.Menu()
        #log Menu
        log_menu = wx.Menu()
        log_menu.Append(2, 'Alerts')#2
        log_menu.Append(6, 'Updates')#3
        log_menu.Append(7, 'Systray')#4
        #service Menu
        svc_menu = wx.Menu()
        svc_menu.Append(8, 'Stop')#6
        svc_menu.Append(9, 'Start')#7
        svc_menu.Append(4, 'Restart')#8
        #ban Menu
        ban_menu = wx.Menu()
        ban_menu.Append(11,'Add Ban')#9
        ban_menu.Append(12,'Remove Ban')#10

        #now create the final menu
        menu.Append(1, 'Settings')#1
        menu.Append(wx.ID_ANY, 'Logs', log_menu)
        #menu.AppendMenu(wx.ID_ANY, 'Logs', log_menu)
        menu.Append(3, 'Check for Updates')#5
        menu.AppendMenu(wx.ID_ANY,'Service',svc_menu)
        #menu.AppendMenu(wx.ID_ANY, 'Ban Options',ban_menu)
        #menu.Append(15, 'Console')
        menu.Append(5, 'Exit')#11
        return menu
    

   
    def on_taskbar_close(self, event):
        """
        Closes systray app after showing a balloon alert

        """
        dial = wx.MessageDialog (self.frame, 'Are you sure you want to exit?', 'Confirm Exit',
        wx.YES_NO | wx.ICON_EXCLAMATION )
        
        
        if dial.ShowModal() == wx.ID_YES:
            dial.Destroy()
            self.ShowBalloon("Artillery systray","Shutting down.....")
            #logs.info("Artillery systray Shutting down.....")
            self.frame.OnClose(wx.EVT_CLOSE)
        else:
            dial.Destroy()
            return

    def start_alert_listener(self):
        """
        start a listener to recieve alerts from artillery
        """
        threading.Thread(target=alert_listener).start()
        threading.Thread(target=self.alert_monitor).start()
    
    def alert_monitor(self):
        def monitor():
            logs.info("starting event monitor")
            while True:
                time.sleep(10)
                global have_alerts
                global incoming_alerts
                if have_alerts == False:
                    pass
                else:
                    #we have alerts
                    msg = incoming_alerts
                    self.ShowBalloon(title="Artillery - Advanced Threat Detection",text=msg,msec=500)
                    have_alerts = False
                    incoming_alerts = ""
        monitor()

    
class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    """
    handles recieving alerts/updates from artillery process
    """

    def setup(self) -> None:

        return super().setup()
    
    def handle(self):
        recv1 = self.request.recv(1024)
        ip = self.client_address[0]
        msg = f"{str(recv1)}"
        logs.info(f"alert recieved: {str(msg)}")
        self.request.send(b"ok")
        self.show_balloon_alert(msg)
        
    def finish(self) -> None:
        return super().finish()
    
    def show_balloon_alert(self,alert):
        '''
        writes alert to msg buffer for notification
        '''
        global incoming_alerts
        global have_alerts
        if have_alerts == False:
            have_alerts = True
            incoming_alerts = alert


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def alert_listener():
    try:
        a = str(CURRENT_SETTINGS.get("BIND_ADDRESS")[0])
        p = str(CURRENT_SETTINGS.get("ALERT_PORT")[0])
        addr = a.strip()
        port = p.strip()
        server = ThreadedTCPServer((addr, int(port)), ThreadedTCPRequestHandler)

        logs.info(f"listening on: {server.server_address[0]} port: {server.server_address[1]}")

        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=server.serve_forever,name="systray alert listener thread")
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        logs.info(f"Server loop running in thread: {server_thread.name}") 

        server.serve_forever()
        # time.sleep(30)
    except KeyboardInterrupt:
        server.shutdown()
        print("end")

class LaunchSysTray(wx.Frame):
    """
    main frame for handling and controlling artillery output.
    """
    def __init__(self, parent,id,title):
        wx.Frame.__init__(self, parent, id=wx.ID_ANY, title=u"Artillery Shell", pos=wx.DefaultPosition, size=wx.Size(500, 362), style=wx.DEFAULT_FRAME_STYLE | wx.TAB_TRAVERSAL | wx.BORDER_THEME)
        self.SetIcon(wx.Icon('.//src//icons//settings_icon.ico', wx.BITMAP_TYPE_ICO))
        self.SetSizeHints(wx.DefaultSize, wx.DefaultSize)
        logs.info("Loading console frame")
        bSizer1 = wx.BoxSizer(wx.VERTICAL)
        self.grab_path = wx.StandardPaths.Get()
        #this list handles keyboard input from the user and map to appropriate function
        self.cmd_input = []
        self.prompt = ">>>"
        # main program output frame
        self.output_frame = wx.richtext.RichTextCtrl(self, wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.DefaultSize, 0 | wx.VSCROLL | wx.HSCROLL | wx.NO_BORDER | wx.WANTS_CHARS)
        bSizer1.Add(self.output_frame, 1, wx.EXPAND | wx.ALL, 0)
        self.SetSizer(bSizer1)
        self.Layout()
        #create a statusbar for bottom of window to recieve updates during operation
        self.m_statusBar2 = self.CreateStatusBar(2, wx.STB_SIZEGRIP, wx.ID_ANY)
        # create mainmenubar @ top of window
        self.main_menubar = wx.MenuBar(0)
        # control menu ###############################################################################################
        self.control_menu = wx.Menu()
        self.start_control = wx.MenuItem(self.control_menu, wx.ID_ANY, u"Start...", wx.EmptyString, wx.ITEM_NORMAL)
        self.control_menu.Append(self.start_control)
        self.Bind(wx.EVT_MENU, self.on_start_service, self.start_control)
        # stop control button
        self.stop_control = wx.MenuItem(self.control_menu, wx.ID_ANY, u"Stop...", wx.EmptyString, wx.ITEM_NORMAL)
        self.control_menu.Append(self.stop_control)
        self.Bind(wx.EVT_MENU, self.on_stop_service, self.stop_control)
        # self.control_menu.Bind()
        # restart control button
        self.restart_control = wx.MenuItem(self.control_menu, wx.ID_ANY, u"Restart...", wx.EmptyString, wx.ITEM_NORMAL)
        self.control_menu.Append(self.restart_control)
        self.Bind(wx.EVT_MENU, self.on_restart_service, self.restart_control)
        # exit control button
        self.exit_control = wx.MenuItem(self.control_menu, wx.ID_ANY, u"Exit...", wx.EmptyString, wx.ITEM_NORMAL)
        self.Bind(wx.EVT_MENU, self.OnTaskBarDeactivate, self.exit_control)
        
        #set the frame to just minimize when close button is pressed
        #self.Bind(wx.EVT_MENU, self.OnTaskBarDeactivate, self.exit_control)
        #self.Bind(wx.EVT_CLOSE,self.OnTaskBarDeactivate)
        self.control_menu.Append(self.exit_control)
        self.main_menubar.Append(self.control_menu, u"Control")
        logs.info("Done loading control menu")
        # settings menu ##############################################################################################
        self.settings_menu = wx.Menu()
        #self.current_settings = wx.MenuItem(self.settings_menu, wx.ID_ANY, u"View current...", wx.EmptyString, wx.ITEM_NORMAL)
        #self.settings_menu.Append(self.current_settings)
        # modify settings button
        self.modify_settings = wx.MenuItem(self.settings_menu, wx.ID_ANY, u"Manage...", wx.EmptyString, wx.ITEM_NORMAL)
        self.settings_menu.Append(self.modify_settings)
        self.Bind(wx.EVT_MENU, self.on_open_settings, self.modify_settings)
        # # import settings button
        # self.import_settings = wx.MenuItem(self.settings_menu, wx.ID_ANY, u"Import...", wx.EmptyString, wx.ITEM_NORMAL)
        # self.settings_menu.Append(self.import_settings)
        # # export settings button
        # self.export_settings = wx.MenuItem(self.settings_menu, wx.ID_ANY, u"Export...", wx.EmptyString, wx.ITEM_NORMAL)
        # self.settings_menu.Append(self.export_settings)
        # self.Bind(wx.EVT_MENU, self.on_export_settings_file, self.export_settings)
        self.main_menubar.Append(self.settings_menu, u"Settings")
        logs.info("Done loading settings menu")
        # banlist menu ###############################################################################################
        self.banlist_menu = wx.Menu()
        self.view_current = wx.MenuItem(self.banlist_menu, wx.ID_ANY, u"View current...", wx.EmptyString, wx.ITEM_NORMAL)
        self.banlist_menu.Append(self.view_current)
        self.add_entry = wx.MenuItem(self.banlist_menu, wx.ID_ANY, u"Add entry...", wx.EmptyString, wx.ITEM_NORMAL)
        self.banlist_menu.Append(self.add_entry)
        self.Bind(wx.EVT_MENU, self.on_add_banlist_entry, self.add_entry)
        self.remove_entry = wx.MenuItem(self.banlist_menu, wx.ID_ANY, u"Remove entry...", wx.EmptyString, wx.ITEM_NORMAL)
        self.banlist_menu.Append(self.remove_entry)
        self.Bind(wx.EVT_MENU, self.on_remove_banlist_entry, self.remove_entry)
        self.export_current = wx.MenuItem(self.banlist_menu, wx.ID_ANY, u"Export...", wx.EmptyString, wx.ITEM_NORMAL)
        self.banlist_menu.Append(self.export_current)
        self.main_menubar.Append(self.banlist_menu, u"Banlist")
        logs.info("Done loading banlist menu")
        # log menu ####################################################################################################
        self.logs_menu = wx.Menu()
        self.view_logs = wx.MenuItem(self.logs_menu, wx.ID_ANY, u"View...", wx.EmptyString, wx.ITEM_NORMAL)
        self.logs_menu.Append(self.view_logs)
        self.save_logs = wx.MenuItem(self.logs_menu, wx.ID_ANY, u"Save...", wx.EmptyString, wx.ITEM_NORMAL)
        self.Bind(wx.EVT_MENU, self.on_save_log_file, self.save_logs)
        self.logs_menu.Append(self.save_logs)
        self.clear_logs = wx.MenuItem(self.logs_menu, wx.ID_ANY, u"Clear...", wx.EmptyString, wx.ITEM_NORMAL)
        self.logs_menu.Append(self.clear_logs)
        self.main_menubar.Append(self.logs_menu, u"Logs")
        logs.info("Done loading log menu")
        # map menu ####################################################################################################
        self.map_menu = wx.Menu()
        self.open_map = wx.MenuItem(self.map_menu, wx.ID_ANY, u"Open...", wx.EmptyString, wx.ITEM_NORMAL)
        self.map_menu.Append(self.open_map)
        self.main_menubar.Append(self.map_menu, u"Map")
        #help menu ####################################################################################################
        self.help_menu = wx.Menu()
        self.about_help = wx.MenuItem(self.help_menu, wx.ID_ANY, u"About...", wx.EmptyString, wx.ITEM_NORMAL)
        self.help_menu.Append(self.about_help)
        self.Bind(wx.EVT_MENU, self.OnAbout, self.about_help)
        self.homepage_help = wx.MenuItem(self.help_menu, wx.ID_ANY, u"Homepage", wx.EmptyString, wx.ITEM_NORMAL)
        self.help_menu.Append(self.homepage_help)
        self.Bind(wx.EVT_MENU, self.OnHompage, self.homepage_help)
        #self.help_help = wx.MenuItem(self.help_menu, wx.ID_ANY, u"Help...", wx.EmptyString, wx.ITEM_NORMAL)
        #self.help_menu.Append(self.help_help)
        #self.Bind(wx.EVT_MENU, self.GetHelp, self.help_help)
        self.main_menubar.Append(self.help_menu, u"Help")
        #set final menubar ############################################################################################
        self.SetMenuBar(self.main_menubar)
        # Begin main code section #####################################################################################
        # get_os_info = wx.GetOsVersion()
        # process_id = wx.GetProcessId()
        self.output_frame.WriteText(self.prompt)
        # initialize systray app and bind for close
        #self.sys_tray_app = SysTrayApp(self)
        self.Bind(wx.EVT_CLOSE, self.OnTaskBarDeactivate)
        self.output_frame.Bind(wx.EVT_CHAR_HOOK, self.OnKeyDown)
        self.tskic = SysTrayApp(self)
        logs.info("done loading console")
        #wx.LogStatus(self, str(process_id))

    def OnKeyDown(self, event):
        #cmd = []
        """grabs keystrokes from the main frame and processes based on input"""
        rawkeycode = event.GetRawKeyCode()
        #print(f"raw key code : {str(rawkeycode)}")
        keycode = event.GetKeyCode()
        #print(f"reg key code: {str(keycode)}")
        letter_value = chr(keycode).lower()
        #print(f"{letter_value} = {ord(letter_value)}")
        self.output_frame.WriteText(letter_value)
        self.cmd_input.append(letter_value)
        if keycode == wx.WXK_BACK:
            self.cmd_input.clear()
            self.output_frame.Clear()
            self.output_frame.WriteText(self.prompt)
        if keycode == wx.WXK_SHIFT:
            print("shift pressed")
        if keycode == wx.WXK_RETURN:
            self.cmd_input.remove('\r')
            self.command = "".join(self.cmd_input)
            #self.output_frame.WriteText(f"command recieved: {str(self.command)}")
            self.cmd_input.clear()
            #
            if self.command == "help":
                self.GetHelp()
                self.output_frame.WriteText(self.prompt)
            elif self.command == "start":
                self.output_frame.WriteText(self.prompt)
            elif self.command == "exit":
                self.OnClose(wx.EVT_CLOSE)
            elif self.command == "query":
                self.query_system_settings()
            else:
                self.output_frame.WriteText("unknown command")
                self.output_frame.Newline()
                self.output_frame.WriteText(self.prompt)

    def OnHompage(self, event):
        """
        Opens Project Homepage using default browser.
        uses webrowser module from stdlib
        """
        hompage = "https://github.com/russhaun/artillery/tree/pyinstaller_branch"
        #opens in new tab if browser is open
        webbrowser.open(url=hompage, new=2)

    def OnAbout(self, event):
        """
        Creates about dialog box with info on software
        AboutDialogInfo() is used to create with all info
        needed. AboutBox() then is used to display information
        """
        about = AboutDialogInfo()
        about.SetName("Artillery Shell")
        about.SetVersion("1.0 (beta)")
        #returns icon from MainWindow class
        icon = wx.GetApp().GetTopWindow().GetIcon()
        about.SetIcon(icon=icon)
        about.SetDescription("An interface to manage\n your artillery instance.")
        about.AddDeveloper("Just a guy in a garage somewhere")
        AboutBox(about)
        return
    
    def OnTaskBarActivate(self, event):
        if not self.IsShown():
            self.Show()

    def OnTaskBarDeactivate(self, event):
        if self.IsShown():
            self.Hide()

    def check_for_alerts(self,event):
        '''checks for alert from artillery listener'''
        pass


    def on_check_for_updates(self,event):
        """pulls down latest version info from github to compare with client.if version is not larger
        then client just continues and no updates are performed. requests will be replaced with Request module at some point
        this will be reworked to use tuples instead of strings in future
        """
        logs.info("Checking for updates")
        info = []
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'}
        url = 'https://raw.githubusercontent.com/russhaun/Updates/master/Artillery/ver.txt'
        r = requests.get(url, headers=headers)
        with open("srv_ver.txt", 'w') as v:
                #response is binary have to convert it to utf-8
                response = r.content
                decoded = response.decode(encoding="utf-8")
                #add the version number to our list
                info.append(decoded)
                #used by update binary
                v.write(decoded)
                logs.info("Response from Server:  ok...")
        v.close()
        s_ver = info[0]
        #strip all spaces and such to make sure no issues with compare
        srv_ver = s_ver.strip()
        cli_ver = client_ver.strip()
        #compare client/server versions if server is newer update else pass
        if srv_ver == cli_ver:
            msg = "No updates were detected you are on the latest version"
            logs.info(msg)
            msgbox = wx.MessageDialog(parent=self,message=msg, caption="No updates detected",style=wx.OK)
            get_box = msgbox.ShowModal()
            #delete the version info file. we dont need it any more
            subprocess.call(['cmd', '/C', 'del', 'srv_ver.txt'],creationflags=subprocess.CREATE_NO_WINDOW)
            if get_box == wx.ID_OK:
                #msgbox.EndModal()
                pass
        else:
            if srv_ver > cli_ver:
                msg = "Updates have been detected would you like to apply them now?"
                msgbox = wx.MessageDialog(parent=self,message=msg, caption="Updates detected",style=wx.OK|wx.CANCEL)
                get_box = msgbox.ShowModal()
                if get_box == wx.ID_OK:
                    #start update routine
                    logs.info("ok was pressed starting updates")
                    cmd = [update_app]
                    ctypes.windll.shell32.ShellExecuteW(
                            None,
                            u"runas",
                            cmd[0],
                            None,
                            None,
                            1
                        )
                    #subprocess.run(update_app ,shell=False, check=False,creationflags=subprocess.CREATE_NEW_CONSOLE)
                if get_box == wx.ID_CANCEL:
                    #log that cancel was pressed declining updates
                    logs.info("cancel was pressed declining updates")
        return(srv_ver)
    

    def on_get_service_status(self, event):
        """
        returns service status
        """
        #use subprocess to return service status
        cmd = [service_app]
        ctypes.windll.shell32.ShellExecuteW(
                None,
                u"runas",
                cmd[0],
                'status',
                None,
                1
            )

    

    def on_start_service(self, event):
        """
        runs ArtilleryService with approprite cmds
        """
        cmd = [service_app]
        ctypes.windll.shell32.ShellExecuteW(
                None,
                u"runas",
                cmd[0],
                'start',
                None,
                1
            )
        pass

    def on_stop_service(self, event):
        """
        stops ArtilleryService with approprite cmds
        """
        cmd = [service_app]
        ctypes.windll.shell32.ShellExecuteW(
                None,
                u"runas",
                cmd[0],
                'stop',
                None,
                1
            )
        pass

    def on_restart_service(self, event):
        """
        using start/stop_service() functions restarts ArtilleryService with approprite cmds
        """
        logs.info("Trying to restart service")
        self.on_stop_service(event)
        #more then enough time to wait maybe even less?
        time.sleep(5)
        self.on_start_service(event)
        

    def on_open_settings(self, event):
        """
        Opens the settings app. uses subprocess
        """ 
        cmd = [settings_app]
        ctypes.windll.shell32.ShellExecuteW(
                None,
                u"runas",
                cmd[0],
                None,
                None,
                1
            )

    # def on_get_current_settings(self, event):
    #     """
    #     Opens settings app in a seperate window
    #     """
    #     # services_app = wx.App()
    #     # MainServicesFrame().Show()
    #     # services_app.MainLoop()
    #     # return
    #     pass
    
    def on_export_settings_file(self, event):
        """
        saves config file to a location of your choosing using wx.FileDialog()
        after setting default name
        """
        #set default directory and file name
        backup_file_name = "artillery_settings.txt"
        documents_folder = self.grab_path.GetDocumentsDir()
        filepkr = wx.FileDialog(self, "Save settings as...", defaultDir=documents_folder, defaultFile=backup_file_name, style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT, pos=wx.DefaultPosition, name="Save File as...")
        #show the window
        filepkr_window = filepkr.ShowModal()
        if filepkr_window == wx.ID_CANCEL:
            #then they clicked cancel just return
            return
        else:
            #they clicked save do work here
            print(f"Chosen filename: {filepkr.GetFilename()}")
            print(f"Selected path: {filepkr.GetDirectory()}")
            #set the filename and save path
            filename = filepkr.GetFilename()
            savepath = filepkr.GetDirectory()
            #open existing config file
            #
            #print(self.grab_path.GetConfigDir())
            #print(self.grab_path.GetTempDir())
            #print(f"Documents path from wx.StandaardPaths: {self.grab_path.GetDocumentsDir()}")
            #print(self.grab_path.GetDataDir())
            #print(filepkr.GetCurrentlySelectedFilename())
            return
        
    def GetHelp(self,e):
        #keycode = event.GetKeyCode()
        #print(keycode)
        print("hey help")

    def on_view_banlist(self,e):
        """
        opens current balist for viewing with default txt viewer
        """
        pass

    def on_query_system_settings(self,e):
        """
        queries symbol index of GLOBAL_SETTINGS dict and returns value
        """
        
        text = wx.TextEntryDialog(self, "Setting to return:", caption="Query system values", value=wx.EmptyString, style=wx.TextEntryDialogStyle, pos=wx.DefaultPosition)
        text.ForceUpper()
        show_window = text.ShowModal()
        if show_window == wx.ID_OK:
            # value = text.GetValue()
            # setting = GLOBAL_SETTINGS.get(value)
            # self.output_frame.WriteText(setting[0])
            # self.output_frame.Newline()
            # self.output_frame.WriteText(self.prompt)
            pass

    def on_add_banlist_entry(self, event):
        """
        adds an entry to banlist by using wx.TextEntryDialog()
        by asking user what ip to remove. It then adds the
        entry to banlist and routing table
        """
        def create_entry():
            text = wx.TextEntryDialog(self, "Input ip to add:", caption="Add banned ip", value=wx.EmptyString, style=wx.TextEntryDialogStyle, pos=wx.DefaultPosition)
            show_window = text.ShowModal()
            if show_window == wx.ID_OK:
                #grab input value and save
                value = text.GetValue()
                #add value to banlist
                #add value to routing table
                #return status to console
        #         self.output_frame.Newline()
        #         self.output_frame.WriteText(value)
        #         self.output_frame.Newline()
        #         self.output_frame.WriteText(self.prompt)
        create_entry()
                #pass
        
        

    def on_remove_banlist_entry(self, event):
        """
        removes an entry from banlist by using wx.TextEntryDialog()
        by asking user what ip to remove. It then removes the
        entry from banlist and routing table
        """
        def delete_route(ip):
            try:
                subprocess.call(['cmd', '/C', 'route', 'delete', ip], shell=True)
            except subprocess.CalledProcessError as e:
                print(e)
            
        text = wx.TextEntryDialog(self, "input ip to remove", caption="Remove banned ip", value=wx.EmptyString, style=wx.TextEntryDialogStyle, pos=wx.DefaultPosition)
        show_window = text.ShowModal()
        if show_window == wx.ID_OK:
            value = text.GetValue()
            #grab input value and save
            #add value to banlist
            #add value to routing table
            #delete_route(value)
            #return status to console
            self.output_frame.Newline()
            self.output_frame.WriteText(value)
            self.output_frame.Newline()
            self.output_frame.WriteText(self.prompt)
            #print(value)
        #pass

    def on_export_banlist(self, event):
        """
        saves current banlist to a location of your choosing
        """
        pass

    def on_save_log_file(self, event):
        """
        saves log file to a location of your choosing using wx.FileDialog()
        after asking for a file name
        """
        # backup_file_name = "artillery_logs.txt"
        # documents_folder = self.grab_path.GetDocumentsDir()
        # filepkr = wx.FileDialog(self, "Save log as...", defaultDir=wx.EmptyString, defaultFile=backup_file_name, style=wx.FD_SAVE, pos=wx.DefaultPosition, name="Save File as...")
        # filepkr_window = filepkr.ShowModal()
        # if filepkr_window == wx.ID_SAVE:
        #     print("closed file picker")
        pass

    def on_view_log_file(self, event):
        """
        opens current alert log for viewing with default txt viewer

        """
        subprocess.run(["notepad.exe", logpath], shell=False, start_new_session=True, check=False)

        pass
    def on_view_systray_log_file(self,e):
        """
        opens current systray log for viewing with default txt viewer
        """
        subprocess.run(["notepad.exe", traylogs], shell=False, start_new_session=True, check=False)

    def on_view_updates_log_file(self,e):
        """
        opens current updates log for viewing with default txt viewer
        """
        subprocess.run(["notepad.exe", updatelogs], shell=False, start_new_session=True, check=False)
        

    def on_view_settings_log_file(self,e):
        """
        opens current settings log for viewing with default txt viewer
        """
        #subprocess.run(["notepad.exe", settingslogs], shell=False, start_new_session=True, check=False)
        pass

    def on_clear_log_file(self, event):
        """
        clears existing log file.
        """
        pass

    def OnClose(self, event):
        """
        cleans up program by closing active threads,
        killing trayapp then finally closing software
        """
        logs.info("Closing systray")
        self.tskic.Destroy()
        app.OnClose()



class MainApp(wx.App):
    """
    systray app launcher.
    """
    def OnInit(self):
        self.frame = LaunchSysTray(None, -1, ' ')
        self.frame.Show(False)
        self.SetTopWindow(self.frame)
        return True
    
    def OnClose(self):
        """
        Exits main app loop
        """
        logs.info("killing main app")
        self.Destroy()

if __name__ == "__main__":
    app = MainApp(0)
    app.MainLoop()
