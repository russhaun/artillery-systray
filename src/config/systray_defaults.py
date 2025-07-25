'''
    Config module for configuration reading/writing/translating for Artillery systray. We do a read of every setting availible and store for access
for use in app elsewhere. all values grabbed from config file. if no config file exists one is created with defaults.
All values are held in memory to avoid doing reads of config file that way it is run once and we just import setting returned and use.
It generates 2 dictionaries. 1 holds current settings from config file. The other holds global system values such as app path. theses dicts are
imported into other modules for use 

'''
import os
import platform
import sys
import re
import socket
#from threading import Timer

CURRENT_SETTINGS = {}
GLOBAL_SETTINGS = {}


class global_init:
    def __init__(self) -> None:
        pass

    def set_globals(self):
        """
        Configures global system defaults that software uses based on platform
        """
        if 'win32' in sys.platform:
            programfolder = os.environ["PROGRAMFILES(x86)"]
            programdata = os.environ["PROGRAMDATA"]
            globaldefaults = GLOBAL_SETTINGS
            globaldefaults["PLATFORM"] = ["win32", ""]
            globaldefaults["APP_NAME"] = ["Artillery SysTray", ""]
            globaldefaults["SYSTRAY_APP_PATH"] = [programdata + "\\artillery\\systray", ""]
            globalappath = self.get_value("SYSTRAY_APP_PATH")
            globaldefaults["APP_FILE"] = [globalappath + "\\trayapp.exe", ""]
            globaldefaults["CONFIG_FILE"] = [globalappath + "\\config", ""]
            globaldefaults["SYSTRAY_LOG_FILE"] = [globalappath + "\\logs\\trayapp_logs.txt",""]
            globaldefaults["ARTILLERY_LOG_FILE"] = [programfolder + "\\Artillery\\logs\\alerts.log", ""]
            globaldefaults["UPDATE_LOG_FILE"] = [globalappath+ "\\logs\\updates.txt"]
            globaldefaults["ICON_PATH"] = [globalappath + "\\src\\icons", ""]
            globaldefaults["SETTINGS_APP"] = [programdata+ "\\Artillery\\systray\\settingsMGR.exe", ""]
            globaldefaults["UPDATE_APP"] = [programdata+"\\Artillery\\systray\\ArtilleryUpdate.exe",""]
            globaldefaults["SERVICE_MGR"] = [programdata+"\\Artillery\\systray\\srvcmgr.exe",""]
            hostname = self.get_hostname()
            globaldefaults["HOSTNAME"] = [hostname]
            getplatform = self.get_value("PLATFORM")[0]
            self.get_host_OS(getplatform)

    def get_value(self, config):
        """
        returns a value from global config
        """
        value = GLOBAL_SETTINGS.get(config)
        return value[0]

    def get_host_OS(self, pf):
        """
        set host os values in GLOBAL_SETTINGS  dict
        """
        if pf == "win32":
            windows_ver = platform.platform(terse=True)
            build = platform.win32_ver()
            edition = platform.win32_edition()
            GLOBAL_SETTINGS["HOST_OS"] = [f"{windows_ver} {edition}", build[1]]
        elif pf == "linux" or "darwin":
            pass


    def get_hostname(self) -> str:
        """
        returns hostname of machine
        """
        return socket.gethostname()

    def set(self):
        """
        sets up global values
        """
        self.set_globals()


class config_init:
    """
    This class is designed to configure all needed settings to handle
    creating/updating a new/existing config file to run systray based on 
    platform with help from the class above. Once complete all 
    values are retrieved from memory during program operation in the form of a dict()
    if no config file exists one will be created. Once a config exists it will use 
    those values and update if needed with new config options
    
    """
    def __init__(self) -> None:
        # import our global class and initialize values
        global_values = global_init()
        global_values.set()
        self.default_settings = {}
        self.current_settings = {}
        self.settings_to_update = {}
        configfile = GLOBAL_SETTINGS.get("CONFIG_FILE")
        self.configpath = configfile[0]
    

    def generate_default_config(self) -> dict:
        """
        Generate sane defaults depending on platform. Returns a dict of lists
        for use in code.


         setting_header: [setting_value, setting_comment]

         Maps class dict to global dict 'CURRENT_SETTINGS' to use after this function runs.
         and to also export elsewhere in code. the goal is to do all configuration at runtime
         to eliminate issues
        """
        #set base options
        configdefaults = CURRENT_SETTINGS
        configdefaults["AUTO_UPDATE"] = ["OFF", "DO YOU WANT TO DO AUTOMATIC UPDATES - ON OR OFF."]
        configdefaults["UPDATE_FREQUENCY"] = ["604800", "UPDATE FREQUENCY, ONLY VALID ON WINDOWS (DEFAULT IS 7 DAYS)."]
        configdefaults["ALERT_PORT"] = ["10080", "PORT TO LISTEN ON FOR ALERTS"]
        configdefaults["BIND_ADDRESS"] = ["127.0.0.1","BIND ADDRESS FOR ALERTS"]
        configdefaults["SYSTRAY_VER"] = ["1.0.0","LK VERSION OF SYSTRAY APP"]
        configdefaults["ARTILLERY_VER"] = ["3.0.0","LK VERSION OF ARTILLERY"]
        #add options to dict
        keyorder = []
        keyorder.append("AUTO_UPDATE")
        keyorder.append("UPDATE_FREQUENCY")
        keyorder.append("ALERT_PORT")
        keyorder.append("BIND_ADDRESS")
        keyorder.append("SYSTRAY_VER")
        keyorder.append("ARTILLERY_VER")
        #append all the keys
        for key in configdefaults:
            if key not in keyorder:
                keyorder.append(key)
        #check for missing values in existing config flag
        #check for existence of config file flag
        missing_values = False
        createnew = False
        #if the config exists check for any changes since last update
        if os.path.isfile(self.configpath):
            for configkey in configdefaults:
                #check the config file for setting header
                if self.config_exists(configkey):
                    #update our internal dict with those values
                    currentcomment = configdefaults[configkey][1]
                    currentvalue = self.read_config_file(configkey)
                    configdefaults[configkey] = [currentvalue, currentcomment]
                else:
                    #detect which keys are not present in current file and add them to a list
                    missing_keys = []
                    missing_keys.append(configkey)
                    #trigger update config flag
                    missing_values = True
                    #add all the values to our update dict
                    for item in missing_keys:
                        item = self.get_value(item)
                        comment = configdefaults[configkey][1]
                        self.settings_to_update[configkey] = [item, comment]
        else:
            #create a whole new file as no config exists
            createnew = True
            #if createnew is True:
            #generate defaults to write to new file
            for configkey in CURRENT_SETTINGS:
                currentcomment = CURRENT_SETTINGS[configkey][1]
                currentvalue = self.get_default_config(configkey)
                CURRENT_SETTINGS[configkey] = [currentvalue, currentcomment]
            #create a new file to use for settings
            self.create_default_config(self.configpath, configdefaults, keyorder)
        
        #This is to add any missing values to config file skipped if none
        if missing_values is True:
            print("there are missing values from the config file")
            self.update_existing_config()
        else:
            #pass as no conditions fired nothing to do with config
            pass

        #Base Dictionary has been created/updated for global use

    def get_value(self, config):
        """
        returns a value from global config
        """
        value = CURRENT_SETTINGS.get(config)
        return value[0]

    def get_default_config(self, config):
        """
        grabs value from master dictionary to use when creating a brand new config file
        """
        value = CURRENT_SETTINGS.get(config)
        return value

    def update_existing_config(self):
        """
        updates existing config file if changes are detected
        """
        confile = open(self.configpath, "a")
        with confile as update:
            #jump to end of file
            update.seek(0, os.SEEK_END)
            #add the missing values from our dict
            for key in self.settings_to_update:
                value = self.settings_to_update.get(key)
                update.write(f"\n#{value[1]}\n{key}= {value[0]}\n")

    def read_config_file(self, setting):
        """
        Checks for config setting in config file
        returns value
        """
        fileopen = open(self.configpath, "r")
        for line in fileopen:
            if not line.startswith("#"):
                match = re.search(setting + "=", line)
                if match:
                    line = line.rstrip()
                    line = line.replace('"', "")
                    line = line.split("=")
                    return line[1]
        pass

    def config_exists(self, setting):
        """
        Checks for existence of config setting in config file
        returns True or False

        """
        fileopen = open(self.configpath, "r")
        paramfound = False
        for line in fileopen:
            if not line.startswith("#"):
                match = re.search(setting + "=", line)
                if match:
                    paramfound = True
        return paramfound

    def create_default_config(self, configpath, configdefaults, keyorder):
        """
        Writes out a default config if none present
        """
        '''builds out config file with some sane defaults
        according to platform and writes it to a file'''
        
        confile = open(configpath, "w")
        banner = "#############################################################################################\n"
        banner += "#\n"
        banner += "# This is the Artillery Systray configuration file. Change these variables and flags to change how\n"
        banner += "# it behaves.\n"
        banner += "#\n"
        banner += "# Artillery SysTray written by: Russell Haun\n"
        banner += "# Website: https://www.binarydefense.com\n"
        banner += "# Email: info [at] binarydefense.com\n"
        banner += "# Download: git clone https://github.com/RussHaun/systray systray/\n"
        banner += "#\n"
        banner += "#############################################################################################\n"
        banner += "#\n"
        confile.write(banner)
        for configkey in keyorder:
            try:
                comment_values = CURRENT_SETTINGS.get(configkey)
                config_values = comment_values[0]
                key = configkey
                #current = f" comment: {config_values[1]} variable: {key} setting: {config_values[0]}"
                #print(current)
                newline_comment = f"\n#{config_values[1]}\n"
                newline_config = f"{key}= {config_values[0]}\n"
                #newline_config = "%s=\"%s\"\n" % (configkey, configdefaults[configkey][0])
                confile.write(newline_comment)
                confile.write(newline_config)
            except KeyError as e:
                print(f"keys not added: {e}")
                
        confile.close()
        print(f"[*] Config file created @ {self.configpath}")
        return

config = config_init()
config.generate_default_config()