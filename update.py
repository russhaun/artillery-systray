import os
import sys
import shutil
import PyInstaller.log
import requests
import subprocess
import time
import ctypes
import wmi
from zipfile import ZipFile
from src.logger.log_handler import file_logger
import wx
from wx.adv import TaskBarIcon

ENABLE_SYSTRAY_UPDATES = False
ENABLE_TESTING = True
programdata = os.environ['ProgramData']
programfiles = os.environ['ProgramFiles(x86)']
g_apppath = os.path.join(programfiles, "Artillery")
g_systray = os.path.join(programdata,"artillery","systray")
#g_apppath = f"{programfiles}\\Artillery"
g_testpath = f"{programdata}\\artillery\\testcopy"
g_configfile = f"{g_apppath}\\config"
icon_file = f"{programdata}\\artillery\\systray\\src\\icons\\settings_icon.ico"
update_file = f"{programdata}\\artillery\\systray\\srv_ver.txt"
srvcmgr = f"{programdata}\\artillery\\systray\\srvcmgr.exe"
systray = f"{programdata}\\artillery\\systray\\trayapp.exe"
#HOME_DIR = f"{programdata}\\artillery"
HOME_DIR = os.getcwd()
ROOT_PATH = str(HOME_DIR)
RELEASE_PATH = f"{ROOT_PATH}\\releases"
ROOT_LOG_PATH = f"{ROOT_PATH}\\logs"
ROOT_LOG_FILE = f"{ROOT_LOG_PATH}\\updates.txt"
ROOT_CONFIG_BACKUP_PATH = f"{ROOT_PATH}\\config_backup"
LOG_PATH = str(ROOT_LOG_PATH)
CONFIG_BACKUP_PATH = str(ROOT_CONFIG_BACKUP_PATH)
CONFIG_EXISTS = 0
logger = file_logger("Updater",ROOT_LOG_FILE)

class SysTray(TaskBarIcon):
    def __init__(self, frame):
        TaskBarIcon.__init__(self)
        self.frame = frame
        self.SetIcon(wx.Icon(icon_file, wx.BITMAP_TYPE_ICO), 'Artillery update')
        self.Bind(wx.EVT_CLOSE,self.OnClose)
        logger.info("starting update app")
        self.InstallUpdates()

    def pause_dialog(self,milli,msg):
        wx.MilliSleep(milli)
        wx.Yield()
        logger.info(msg)

    def InstallUpdates(self):
        """
        Creates a progress dialog box and updates as it is applying updates for Artillery
        """
        with wx.ProgressDialog("Installing Updates","Downloading updates.", maximum=100) as open_dlg:
            open_dlg.SetIcon(wx.Icon(icon_file, wx.BITMAP_TYPE_ICO))
            msg = "Setting up download folders now."
            open_dlg.Update(2,msg)
            self.pause_dialog(3000,msg)
            if os.path.isdir(ROOT_LOG_PATH):
                msg = "Logfile dir exists skipping."
            else:
                msg = "Creating logfile dir."
                os.mkdir(ROOT_LOG_PATH)
            self.pause_dialog(1000,msg)
            open_dlg.Update(4,msg)
            if os.path.isdir(CONFIG_BACKUP_PATH):
                msg = "config backup dir exists skipping."
            else:
                msg = "Creating config backup dir."
                os.mkdir(CONFIG_BACKUP_PATH)
            self.pause_dialog(1000,msg)
            open_dlg.Update(5,msg)
            if os.path.isdir(RELEASE_PATH):
                msg = "Release dir exists skipping."
            else:
                msg = "Creating release dir."
                os.mkdir(RELEASE_PATH)
            self.pause_dialog(1000,msg)
            open_dlg.Update(7,msg)
            info = []
            with open(update_file, 'r') as v:
                    line = v.readline()
                    stripped = line.strip()
                    info.append(stripped)
            #delete the version info file. we dont need it any more
            delete_version_file_string = f"cmd /C del {update_file}"
            #['cmd', '/C', 'del'
            subprocess.call(delete_version_file_string, shell=True, close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW)
            ver = info[0]
            msg = "Downloading files from github."
            self.pause_dialog(1000,msg)
            open_dlg.Update(9,msg)
            #
            try:
                release_url = 'https://codeload.github.com/russhaun/artillery/zip/pyinstaller_branch'
                headers ={'user-agent': 'Artillery Software Updater V1'}
                msg = f"Checking out Artillery repo version {str(ver)}"
                self.pause_dialog(2000,msg)
                open_dlg.Update(10,msg)
                r = requests.get(release_url,headers=headers)
                # make a nice zip file for later use
                ZIPFILE_NAME = ver+".zip"
                with open(ZIPFILE_NAME, "wb") as download_archive:
                    download_archive.write(r.content)
                    download_archive.close()
                    
            except requests.exceptions.ConnectionError:
                raise
            msg = "Checkout Done!"
            self.pause_dialog(2000,msg)
            open_dlg.Update(15,msg)
            wx.MilliSleep(3000)
            with ZipFile(ZIPFILE_NAME, 'r') as extract_archive:
                #change to releasepath folder
                os.chdir(RELEASE_PATH)
                #create name of folder and remove spaces
                r_id =f"{ver}"
                release_id = r_id.strip()
                #make the folder for current release
                if os.path.isdir(release_id):
                    pass
                else:
                    os.mkdir(release_id)
                msg ="Extracting all the files now."
                self.pause_dialog(1000,msg)
                open_dlg.Update(20,msg)
                #extract archive to release folder
                extract_archive.extractall(path=release_id)
                extract_archive.close()
                msg = "Extraction Done!"
                self.pause_dialog(2000,msg)
                open_dlg.Update(25,msg)
             #backup existing config file
            if os.path.isdir(g_apppath):
                msg = "Artillery directory exists."
                self.pause_dialog(500,msg)
                open_dlg.Update(26,msg)
                msg = "Checking for config file."
                self.pause_dialog(1000,msg)
                open_dlg.Update(27,msg)
                if os.path.isfile(g_configfile):
                    global CONFIG_EXISTS
                    CONFIG_EXISTS += 1
                    if os.path.isdir(CONFIG_BACKUP_PATH):
                        msg = "Backing up existing config file."
                        self.pause_dialog(1000,msg)
                        open_dlg.Update(30,msg)
                        #['cmd', '/C', 'copy', g_configfile, CONFIG_BACKUP_PATH]
                        cmdline = f"cmd /C copy {g_configfile} {CONFIG_BACKUP_PATH}"
                        subprocess.run(cmdline, shell=True, close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    logger.info("Config file not found..... continuing")
            #check to see if service is active
            is_active = self.is_artillery_active()
            active = is_active[0]
            #if its active
            if active:
                msg = is_active[2]
                self.pause_dialog(2000,msg)
                open_dlg.Update(35,msg)
                #stop the service
                if ENABLE_TESTING is True:
                    msg = f"Stopping service with pid {str(is_active[1])}"
                    self.pause_dialog(2000,msg)
                    open_dlg.Update(35,msg)
                    #file_log.info(msg)
                    cmd = [srvcmgr]
                    ctypes.windll.shell32.ShellExecuteW(
                        None,
                        u"runas",
                        cmd[0],
                        'stop',
                        None,
                        1
                    )
                else:
                    msg = f"Stopping service with pid {str(is_active[1])}"
                    self.pause_dialog(2000,msg)
                    open_dlg.Update(35,msg)
                    subprocess.run([srvcmgr, 'stop'],shell=False,creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                #just pass and restart later
                msg = is_active[2]
                self.pause_dialog(2000,msg)
                open_dlg.Update(35,msg)
            #remove existing files
            msg= "Removing existing install."
            self.pause_dialog(5000,msg)
            open_dlg.Update(40,msg)
            if ENABLE_TESTING is True:
                #['cmd', '/C', 'rmdir', '/S', '/Q', g_testpath]
                rmdir_string = f"cmd /C rmdir /S /Q {g_testpath}"
                subprocess.call(rmdir_string, shell=True,creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                #['cmd', '/C', 'rmdir', '/S', '/Q', g_apppath]
                rmdir_string = f"cmd /C rmdir /S /Q {g_apppath}"
                subprocess.call(rmdir_string, shell=True,creationflags=subprocess.CREATE_NO_WINDOW)
            msg = "Successfully removed."
            self.pause_dialog(2000,msg)
            open_dlg.Update(45,msg)
            #change to release dir to copy over new files
            os.chdir(f"{release_id}")
            os.chdir('artillery-pyinstaller_branch')
            EXTRACTED = os.getcwd()
            msg = "Copying archive over."
            self.pause_dialog(2000,msg)
            open_dlg.Update(50,msg)
            if ENABLE_TESTING is True:
                shutil.copytree(EXTRACTED, g_testpath)
            else:
                shutil.copytree(EXTRACTED, g_apppath)
            msg = "Creating program directories."
            self.pause_dialog(4000,msg)
            open_dlg.Update(55,msg)
            if CONFIG_EXISTS == 1:
                msg = "Restoring config from backup."
                self.pause_dialog(1000,msg)
                open_dlg.Update(75,msg)
                #['cmd', '/C', 'copy', CONFIG_BACKUP_PATH, g_configfile]
                restore_config_string = f"cmd /C copy {CONFIG_BACKUP_PATH}\\config {g_configfile}"
                subprocess.call(restore_config_string, shell=True, close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW)
                msg = "Restore Complete."
                self.pause_dialog(1000,msg)
                open_dlg.Update(80,msg)
                #restart the service going from here
                msg = "Restarting Artillery."
                self.pause_dialog(3000,msg)
                open_dlg.Update(90,msg)
            if ENABLE_TESTING is True:
                cmd = [srvcmgr]
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    u"runas",
                    cmd[0],
                    'start',
                    None,
                    1
                )
            else:
                subprocess.run([srvcmgr, 'start'],shell=False,creationflags=subprocess.CREATE_NO_WINDOW)
            #unfinished function call will work in systray updates at a future date
            if ENABLE_SYSTRAY_UPDATES is True:
                msg = "Restarting systray....."
                self.pause_dialog(1000,msg)
                open_dlg.Update(91,msg)
            #check to see if service is running
            was_restarted = self.is_artillery_active()
            is_active = was_restarted[0]
            if is_active:
                msg = "Artillery started....."
                self.pause_dialog(2000,msg)
                open_dlg.Update(92,msg)
            msg = "Performing cleanup....."
            self.pause_dialog(3000,msg)
            open_dlg.Update(95,msg)
            #change back to home folder and delete the zip file we dont need it anymore
            os.chdir(ROOT_PATH)
            #['cmd', '/C', 'del', f"{ver}.zip"]
            delete_zip_string = f"cmd /C del {ver}.zip"
            subprocess.call(delete_zip_string, shell=True, close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW)
            msg = "Completing update....."
            self.pause_dialog(3000,msg)
            open_dlg.Pulse(msg)
        #
        time.sleep(2)
        self.show_updates_complete()
        
    def show_updates_complete(self):
        time.sleep(5)
        self.ShowBalloon(title="Update Mgr",text="Updates complete",msec=3000,flags=wx.ICON_INFORMATION)
        self.OnClose(wx.EVT_CLOSE)
    
    def is_artillery_active(self)->tuple[bool,str,str]:
        '''
        checks to see if process is running already.Returns a tuple of bool,pid,msg
        '''
        wmipid = []
        c = wmi.WMI()
        try:
            logger.info('Checking if service is active.....')
            for process in c.Win32_Process(name="artillery.exe"):
                wmipid.append(process.ProcessId)
        except wmi.x_wmi as e:
            logger.error(f"WMI error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        if len(wmipid) == 0:
            pid = "0"
            msg = "Service is not active."
            return (False,pid,msg)
        else:
            pid = wmipid[0]
            msg = f"Service is active with pid of: {str(pid)}"
            return (True,pid,msg)

    def OnClose(self,event):
        time.sleep(3)
        self.frame.OnClose(wx.EVT_CLOSE)
    
class LaunchSysTray(wx.Frame):
    """
    main frame for handling and controlling artillery output.
    """
    def __init__(self, parent,id,title,frame):
        wx.Frame.__init__(self, parent, id=wx.ID_ANY, title=u"Installing updates", pos=wx.DefaultPosition, size=wx.Size(500, 362), style=wx.DEFAULT_FRAME_STYLE | wx.BORDER_THEME)
        self.SetIcon(wx.Icon(icon_file, wx.BITMAP_TYPE_ICO))
        self.SetSizeHints(wx.DefaultSize, wx.DefaultSize)
        self.frame = frame
        self.tskic = SysTray(self)
        bSizer1 = wx.BoxSizer(wx.VERTICAL)
        self.SetSizer(bSizer1)
        self.Layout()

    def OnClose(self,event):
         logger.info("Closing update app")
         sys.exit()

class MainApp(wx.App):
    """
    Update app launcher.
    """
    def OnRun(self):
        self.frame = LaunchSysTray(None, -1, ' ',self)
        self.frame.Show(False)
        self.frame.SetSize(1,1)
        self.SetTopWindow(self.frame)
        
    def OnInit(self):
        self.OnRun()
    
    def OnClose(self):
        """
        Exits main app loop
        """
        self.Destroy()

if __name__ == "__main__":
    APP = MainApp(0)
    APP.MainLoop()
    