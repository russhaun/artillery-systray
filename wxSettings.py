"""
This file contains multiple classes that when combined. create a single
window to manage settings for Artillery on Windows.
"""
import sys
import wmi
import wx
import netifaces
from ipaddress import ip_network
import psutil
import socket
from src.config.settings_defaults import CURRENT_SETTINGS, GLOBAL_SETTINGS, SETTINGS_TO_UPDATE, update_config
from src.logger.log_handler import file_logger
#map local versions of master dict for us
current_settings = CURRENT_SETTINGS
global_settings = GLOBAL_SETTINGS
#flag for notifying of changes
settings_changed = False
settings_to_update = SETTINGS_TO_UPDATE
wmi_search = wmi.WMI()
adapters = wmi_search.Win32_NetworkAdapter()
logger = file_logger("settings",".//logs//settings.log")
logger.info("starting settings mgr")

#define handlers to to deal with controls in the app
class CustomControls():
    """
    This class handles text box input and checkbox enable/disable modes.
    For now i inheret this class where i need it.

    There are only 2 methods needed so far in this app they are:

        OnUpdate_checkbox(key,state) # key is name of setting to change, state is ON or OFF

        OnUpdate_textctrl(key,value) # Key is name of setting to change, value is the changed value

    
    This class will also hold functions that I only want to write once. for ex. things that dont have a defined control
    mostly info type stuff.
    
    """
    def __init__(self) -> None:
        pass


    def OnUpdate_checkbox(self,key,state):

        """
        updates settings dict for changes related to checkboxes
        They all take an either "ON" or "OFF" value
        """
        global settings_changed
        if settings_changed == False:
            settings_changed = True
        if state == True:
            settings_to_update[key] = "ON"
        elif state == False:
            settings_to_update[key] = "OFF"
        return

    def OnUpdate_txtctrl(self,key,value):
        """
        updates settings dict for changes related to texctrls
        """
        global settings_changed
        if settings_changed == False:
            settings_changed = True
        settings_to_update[key] = value
        return
    
    def get_hostname(self):
        """
        Returns active ip of hostmachine
        """
        name = socket.gethostbyname(socket.gethostname())
        return name

    def get_total_open_ports(self):
        """
        counts # of open ports from config file entries for display
        possible to be wrong if some ports were blocked during honeypot startup(eg. port in use)
        better way in progress
        """
        logger.info("Checking total number of open ports.")
        totalopen =[]
        tcp= current_settings.get('TCPPORTS')[0]
        udp = current_settings.get('UDPPORTS')[0]
        #splitout the tcp ports
        tcpline = tcp.replace(",",", ")
        tline = tcpline.split(",")
       #splitout the udp ports
        udpline = udp.replace(",",", ")
        uline = udpline.split(",")
        #add them all to a list
        #and count them
        for item in tline:
            totalopen.append(item)
        for item in uline:
            totalopen.append(item)
        #info is ready for return
        top = f"Total open ports: {str(len(totalopen))}"
        tports = f"TCP Ports: {str(tcpline)}"
        uports = f"UDP Ports: {str(udpline)}"
        return top,tports,uports


    def get_total_banned_ips(self):
        """
        gets current length of banlist by line and returns count
        minus the file header.
        """
        current_count =0
        banfile = global_settings.get('BANLIST')[0]
        with open(banfile,"r",encoding="utf-8") as totalips:
            for line in totalips:
                current_count+=1
        #remove lines fron banlist header
        final_count = current_count - 13
        #print(f"Total banned ips: {str(final_count)}")
        return f"Total banned ips: {str(final_count)}"

        

    def get_total_availible_services(self):
        pass

    def get_enabled_services(self):
        pass

    def is_artillery_active(self)->tuple[bool,str,str]:
        '''
        checks to see if process is running already.Returns a tuple of bool,pid,msg
        '''
        wmipid = []
        c = wmi.WMI()
        try:
            #print('[*] Checking if service is active.....')
            logger.info('[*] Checking if service is active.....')
            for process in c.Win32_Process(name="artillery.exe"):
                # print(process.ProcessId)
                wmipid.append(process.ProcessId)
        except wmi.WMI_EXCEPTIONS as a:
            pass
        if len(wmipid) == 0:
            pid = "0"
            msg = "Service is not active."
            logger.warning(msg)
            return (False,pid,msg)
        else:
            pid = wmipid[0]
            msg = f"Service is active with pid of: {str(pid)}"
            logger.info(msg)
            return (True,pid,msg)

# Define the tab content as classes:
class ThreatTab(wx.Panel,CustomControls):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.threatfeed_enable_checkbox = wx.CheckBox(self,-1,"Enable Feeds:",(0,10))
        self.threatfeed_enable_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        self.threatfeed_enable_checkbox.SetToolTip(str(current_settings.get('THREAT_INTELLIGENCE_FEED')[1]).lower())
        if current_settings.get('THREAT_INTELLIGENCE_FEED')[0] == 'ON':
            self.threatfeed_enable_checkbox.SetValue(True)
        self.threatfeed_enable_checkbox.AcceptsFocus()
        self.threatfeed_enable_checkbox.AcceptsFocusFromKeyboard()
        self.threatfeed_enable_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_threat_intelegence_feed)

        self.threat_server_enable_checkbox = wx.CheckBox(self,-1,"Enable Server:",(100,10))
        self.threat_server_enable_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        self.threat_server_enable_checkbox.SetToolTip(str(current_settings.get('THREAT_SERVER')[1]).lower())
        if current_settings.get('THREAT_SERVER')[0] == 'ON':
            self.threat_server_enable_checkbox.SetValue(True)
        self.threat_server_enable_checkbox.AcceptsFocus()
        self.threat_server_enable_checkbox.AcceptsFocusFromKeyboard()
        self.threat_server_enable_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_threatserver)

        self.local_banlist_enable_checkbox = wx.CheckBox(self,-1,"Enable Local Banlist:",(200,10))
        self.local_banlist_enable_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        if current_settings.get('LOCAL_BANLIST')[0] == 'ON':
            self.local_banlist_enable_checkbox.SetValue(True)
        self.local_banlist_enable_checkbox.SetToolTip(str(current_settings.get('LOCAL_BANLIST')[1]).lower())
        self.local_banlist_enable_checkbox.AcceptsFocus()
        self.local_banlist_enable_checkbox.AcceptsFocusFromKeyboard()
        self.local_banlist_enable_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_local_banlist)

        threat_feed_source_label = wx.StaticText(self,-1,"Feeds:",(5,42))
        self.threat_feed_source_input = wx.TextCtrl(self,-1,current_settings.get('THREAT_FEED')[0],(50,40),(200,20))
        self.threat_feed_source_input.SetToolTip(str(current_settings.get('THREAT_FEED')[1]).lower())
        self.threat_feed_source_input.AcceptsFocus()
        self.threat_feed_source_input.AcceptsFocusFromKeyboard()
        self.threat_feed_source_input.Bind(wx.EVT_TEXT,self.OnChange_threatfeed)

        self.source_feeds_checkbox = wx.CheckBox(self,-1,'Extra:',(265,42))
        self.source_feeds_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        self.source_feeds_checkbox.SetToolTip(str(current_settings.get('SOURCE_FEEDS')[1]).lower())
        self.source_feeds_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_sourcefeeds)


        threat_server_location = wx.StaticText(self,-1,"Public:",(5,72))
        self.threat_server_location_input = wx.TextCtrl(self,-1,current_settings.get('THREAT_LOCATION')[0],(50,70),(100,20))
        self.threat_server_location_input.SetToolTip(str(current_settings.get('THREAT_LOCATION')[1]).lower())
        self.threat_server_location_input.AcceptsFocus()
        self.threat_server_location_input.AcceptsFocusFromKeyboard()
        self.threat_server_location_input.Bind(wx.EVT_TEXT,self.OnChange_threat_location)


        threat_server_file = wx.StaticText(self,-1,"Files:",(5,102))
        self.threat_server_file_input = wx.TextCtrl(self,-1,current_settings.get('THREAT_FILE')[0],(50,100),(100,20))
        self.threat_server_file_input.SetToolTip(str(current_settings.get('THREAT_FILE')[1]).lower())
        self.threat_server_file_input.AcceptsFocus()
        self.threat_server_file_input.AcceptsFocusFromKeyboard()
        self.threat_server_file_input.Bind(wx.EVT_TEXT,self.OnChange_threatfile)

        
        
        refresh_interval_label = wx.StaticText(self,-1,"Refresh:",(5,134))
        self.refresh_interval = wx.TextCtrl(self,-1,current_settings.get('ARTILLERY_REFRESH')[0],(50,132),(50,20))
        self.refresh_interval.SetToolTip(str(current_settings.get('ARTILLERY_REFRESH')[1]).lower())
        self.refresh_interval.AcceptsFocus()
        self.refresh_interval.AcceptsFocusFromKeyboard()
        self.refresh_interval.Bind(wx.EVT_TEXT,self.OnChange_refresh_interval)

        self.recycle_ips_checkbox = wx.CheckBox(self,-1,"Recycle IPS:",(115,134))
        self.recycle_ips_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        if current_settings.get('RECYCLE_IPS')[0] == 'ON':
            self.recycle_ips_checkbox.SetValue(True)
        self.recycle_ips_checkbox.SetToolTip(str(current_settings.get('RECYCLE_IPS')[1]).lower())
        self.recycle_ips_checkbox.AcceptsFocus()
        self.recycle_ips_checkbox.AcceptsFocusFromKeyboard()
        self.recycle_ips_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_recycle_ips)
        
    def OnChange_refresh_interval(self,e):
        self.OnUpdate_txtctrl('ARTILLERY_REFRESH',self.refresh_interval.GetValue())

    def OnChange_recycle_ips(self,e):
        self.OnUpdate_checkbox('RECYCLE_IPS',self.recycle_ips_checkbox.IsChecked())

    def OnChange_threat_intelegence_feed(self,e):
        self.OnUpdate_checkbox('THREAT_INTELLIGENCE_FEED', self.threatfeed_enable_checkbox.IsChecked())
    
    def OnChange_threatfeed(self,e):
        self.OnUpdate_txtctrl('THREAT_FEED', self.threat_feed_source_input.GetValue())
    
    def OnChange_threatserver(self,e):
        self.OnUpdate_checkbox('THREAT_SERVER',self.threat_server_enable_checkbox.IsChecked())

    def OnChange_local_banlist(self,e):
        self.OnUpdate_checkbox('LOCAL_BANLIST', self.local_banlist_enable_checkbox.IsChecked())
   
    def OnChange_sourcefeeds(self,e):
        self.OnUpdate_checkbox('SOURCE_FEEDS',self.source_feeds_checkbox.IsChecked())
    
    def OnChange_threat_location(self,e):
        self.OnUpdate_txtctrl('THREAT_LOCATION',self.threat_server_location_input.GetValue())

    def OnChange_threatfile(self,e):
        self.OnUpdate_txtctrl('THREAT_FILE', self.threat_server_file_input.GetValue())

    

    

# Define the tab content as classes:
class DockerTab(wx.Panel,CustomControls):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)

class AboutTab(wx.Panel):
    """Creates about Tab """
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)


class EmailTab(wx.Panel,CustomControls):
    """Creates window for settings related to email"""
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        email_enabled = current_settings.get('EMAIL_ALERTS')[0]
        smtp_user = current_settings.get('SMTP_USERNAME')[0]
        smtp_pass = current_settings.get('SMTP_PASSWORD')[0]
        alert_email = current_settings.get('ALERT_USER_EMAIL')[0]
        smtp_from = current_settings.get('SMTP_FROM')[0]
        smtp_to = current_settings.get('SMTP_ADDRESS')[0]
        smtp_port = current_settings.get('SMTP_PORT')[0]
        timer_enabled = current_settings.get('EMAIL_TIMER')[0]
        email_frequency = current_settings.get('EMAIL_FREQUENCY')[0]
        email_frequency_comment = current_settings.get('EMAIL_FREQUENCY')[1]
        self.enable_email_checkbox = wx.CheckBox(self,-1,"Enable:",(0,10))
        self.enable_email_checkbox.SetToolTip("Should email alerts be sent.")
        if email_enabled == 'ON':
            self.enable_email_checkbox.SetValue(True)
        self.enable_email_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        self.enable_email_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_emailenable)
        self.email_timer_checkbox = wx.CheckBox(self,-1,"Email Timer:",(68,10))
        self.email_timer_checkbox.SetWindowStyleFlag(wx.ALIGN_RIGHT)
        if timer_enabled == "ON":
            self.email_timer_checkbox.SetValue(True)
        self.email_timer_checkbox.SetToolTip("waits X time as defined in Freq: text box before sending emails.This helps to reduce spam as the email handler system has changed.")
        self.email_timer_checkbox.AcceptsFocus()
        self.email_timer_checkbox.AcceptsFocusFromKeyboard()
        self.email_timer_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_emailtimer)

        email_username_label = wx.StaticText(self,-1,"User:",(5,40))
        self.email_username_input = wx.TextCtrl(self,-1,current_settings.get("SMTP_USERNAME")[0],(50,38))
        self.email_username_input.SetToolTip("Enter your username here for starttls authentication.Leave blank for Open relay.")
        self.email_username_input.AcceptsFocus()
        self.email_username_input.AcceptsFocusFromKeyboard()
        self.email_username_input.Bind(wx.EVT_KILL_FOCUS,self.OnChange_smtp_username)

        email_password_label= wx.StaticText(self,-1,"Pass:",(5,70))
        self.email_password_input = wx.TextCtrl(self,-1,smtp_pass,(50,68))
        self.email_password_input.SetToolTip("Enter your email user password here")
        self.email_password_input.AcceptsFocus()
        self.email_password_input.AcceptsFocusFromKeyboard()
        self.email_password_input.Bind(wx.EVT_KILL_FOCUS,self.OnChange_smtp_password)
        frequency_label = wx.StaticText(self,-1,"Freq:",(5,100))
        self.frequency_input = wx.TextCtrl(self,-1,email_frequency,(50,98))
        self.frequency_input.SetToolTip(str(email_frequency_comment).lower())
        self.frequency_input.AcceptsFocus()
        self.frequency_input.AcceptsFocusFromKeyboard()
        self.frequency_input.Bind(wx.EVT_TEXT,self.OnChange_frequency)

        smtpaddress_label = wx.StaticText(self,-1,"Host:",(175,40))
        self.smtp_address_input = wx.TextCtrl(self,-1,smtp_to,(210,38))
        self.smtp_address_input.SetToolTip("smtp address for sending email. default is gmail")
        self.smtp_address_input.AcceptsFocus()
        self.smtp_address_input.AcceptsFocusFromKeyboard()
        self.smtp_address_input.Bind(wx.EVT_TEXT,self.OnChange_smtp_to)

        smtpport_label = wx.StaticText(self,-1,"Port:",(175,70))
        self.smtp_port_input= wx.TextCtrl(self,-1,smtp_port,(210,68))
        self.smtp_port_input.SetToolTip("SMTP port to use for sending emails. default is gmail with TLS.")
        self.smtp_port_input.AcceptsFocus()
        self.smtp_port_input.AcceptsFocusFromKeyboard()
        self.smtp_port_input.Bind(wx.EVT_TEXT,self.OnChange_smtp_port)

        alert_email_label = wx.StaticText(self,-1,"Alerts:",(175,100))
        self.alert_email_input = wx.TextCtrl(self,-1,alert_email,(210,98))
        self.alert_email_input.SetToolTip("This is who to send alerts to. Events will be sent from artillery to this address")
        self.alert_email_input.AcceptsFocus()
        self.alert_email_input.AcceptsFocusFromKeyboard()
        self.alert_email_input.Bind(wx.EVT_TEXT,self.OnChange_alert_email)

        smtp_from_label = wx.StaticText(self,-1,"From:",(175,130))
        self.smtp_from_input = wx.TextCtrl(self,-1,smtp_from,(210,128))
        self.smtp_from_input.SetToolTip("This is who the alerts come from. The email from field will be filled with this value")
        self.smtp_from_input.AcceptsFocus()
        self.smtp_from_input.AcceptsFocusFromKeyboard()
        self.smtp_from_input.Bind(wx.EVT_TEXT,self.OnChange_smtp_from)

    def OnChange_frequency(self,e):
        self.OnUpdate_txtctrl("EMAIL_FREQUENCY",self.frequency_input.GetValue())

    def OnChange_emailenable(self,e):
        self.OnUpdate_checkbox("EMAIL_ALERTS",self.enable_email_checkbox.IsChecked())

    def OnChange_emailtimer(self,e):
        self.OnUpdate_checkbox("EMAIL_TIMER",self.email_timer_checkbox.IsChecked())

    def OnChange_smtp_username(self,e):
        self.OnUpdate_txtctrl("SMTP_USERNAME",self.email_username_input.GetValue())

    def OnChange_smtp_password(self,e):
       self.OnUpdate_txtctrl("SMTP_PASSWORD",self.email_password_input.GetValue())
    
    def OnChange_alert_email(self,e):
        self.OnUpdate_txtctrl("ALERT_USER_EMAIL",self.alert_email_input.GetValue())

    def OnChange_smtp_from(self,e):
        self.OnUpdate_txtctrl("SMTP_FROM",self.smtp_from_input.GetValue())

    def OnChange_smtp_to(self,e):
        self.OnUpdate_txtctrl("SMTP_ADDRESS",self.smtp_address_input.GetValue())

    def OnChange_smtp_port(self,e):
        self.OnUpdate_txtctrl("SMTP_PORT",self.smtp_port_input.GetValue())


class SysLogTab(wx.Panel,CustomControls):
    """Creates window for settings related to syslog"""
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.syslog_type = current_settings.get("SYSLOG_TYPE")[0]
        self.logtype_choice = self.get_syslog_type()
        syslog_type_label = wx.StaticText(self,-1,"Type:",(5,20))
        self.syslog_type_choice = wx.Choice(self, wx.ID_ANY, (50, 18), wx.DefaultSize,self.logtype_choice[0], 0,)
        self.syslog_type_choice.SetSelection(self.logtype_choice[1])
        self.syslog_type_choice.SetToolTip(str(current_settings.get('SYSLOG_TYPE')[1]).lower())
        self.syslog_type_choice.AcceptsFocus()
        self.syslog_type_choice.AcceptsFocusFromKeyboard()
        self.syslog_type_choice.Bind(wx.EVT_CHOICE,self.OnChange_syslog_type)

        self.console_logging_checkbox = wx.CheckBox(self,-1,"Console logging:",(150,20))
        self.console_logging_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        self.console_logging_checkbox.SetToolTip(str(current_settings.get('CONSOLE_LOGGING')[1]).lower())
        if current_settings.get('CONSOLE_LOGGING')[0] == 'ON':
            self.console_logging_checkbox.SetValue(True)
        self.console_logging_checkbox.AcceptsFocus()
        self.console_logging_checkbox.AcceptsFocusFromKeyboard()
        self.console_logging_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_console_logging)



        syslog_host_label = wx.StaticText(self,-1,"Host:",(5,60))
        self.syslog_host_input = wx.TextCtrl(self,-1,current_settings.get('SYSLOG_REMOTE_HOST')[0],(50,58))
        self.syslog_host_input.SetToolTip(str(current_settings.get('SYSLOG_REMOTE_HOST')[1]).lower())
        self.syslog_host_input.AcceptsFocus()
        self.syslog_host_input.AcceptsFocusFromKeyboard()
        self.syslog_host_input.Bind(wx.EVT_TEXT,self.OnChange_syslog_host)

        syslog_port_label = wx.StaticText(self,-1,"Port:",(175,60))
        self.syslog_port_input = wx.TextCtrl(self,-1,current_settings.get('SYSLOG_REMOTE_PORT')[0],(210,58))
        self.syslog_port_input.SetToolTip(str(current_settings.get('SYSLOG_REMOTE_PORT')[1]).lower())
        self.syslog_port_input.AcceptsFocus()
        self.syslog_port_input.AcceptsFocusFromKeyboard()
        self.syslog_port_input.Bind(wx.EVT_TEXT,self.OnChange_syslog_port)

        alert_log_msg_label = wx.StaticText(self,-1,"Alert Msg:",(5,100))
        self.alertlog_input = wx.TextCtrl(self,-1,current_settings.get('LOG_MESSAGE_ALERT')[0],(60,98),(260,25))
        self.alertlog_input.SetToolTip(str(current_settings.get('LOG_MESSAGE_ALERT')[1]).lower())
        self.alertlog_input.AcceptsFocus()
        self.alertlog_input.AcceptsFocusFromKeyboard()
        self.alertlog_input.Bind(wx.EVT_TEXT,self.OnChange_log_msg_alert)

        ban_log_msg_label = wx.StaticText(self,-1,"Ban Msg:",(5,130))
        self.banlog_input = wx.TextCtrl(self,-1,current_settings.get('LOG_MESSAGE_BAN')[0],(60,128),(260,25))
        self.banlog_input.SetToolTip(str(current_settings.get('LOG_MESSAGE_BAN')[1]).lower())
        self.banlog_input.AcceptsFocus()
        self.banlog_input.AcceptsFocusFromKeyboard()
        self.banlog_input.Bind(wx.EVT_TEXT,self.OnChange_log_msg_ban)
    
    
    
    
    def get_syslog_type(self):
        """
        builds list and gets index of type being used on system for syslog type control

        """
        types = ["LOCAL", "FILE", "REMOTE"]
        idx = -1
        for item in types:
            idx=+1
            if item == self.syslog_type:
                #logger.info(f"syslog type match found: {item} at index {str(idx)} for choice control")
                return types,idx
            
    def OnChange_console_logging(self,e):
        self.OnUpdate_checkbox('CONSOLE_LOGGING',self.console_logging_checkbox.IsChecked())
            
    def OnChange_syslog_type(self,e):
        syslog_types = self.logtype_choice[0]
        key = 'SYSLOG_TYPE'
        index = self.syslog_type_choice.GetCurrentSelection()
        value = syslog_types[index]
        self.OnUpdate_txtctrl(key,value)

    def OnChange_syslog_host(self,e):
        self.OnUpdate_txtctrl('SYSLOG_REMOTE_HOST',self.syslog_host_input.GetValue())

    def OnChange_syslog_port(self,e):
        self.OnUpdate_txtctrl('SYSLOG_REMOTE_PORT',self.syslog_port_input.GetValue())

    def OnChange_log_msg_alert(self,e):
        self.OnUpdate_txtctrl('LOG_MESSAGE_ALERT',self.alertlog_input.GetValue())

    def OnChange_log_msg_ban(self,e):
        self.OnUpdate_txtctrl('LOG_MESSAGE_BAN',self.banlog_input.GetValue())


class AntiDosTab(wx.Panel,CustomControls):
    """Creates window for settings related to anti-dos"""
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.anti_dos_enable_checkbox = wx.CheckBox(self,-1,"Enable: ",(0,10))
        self.anti_dos_enable_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        self.anti_dos_enable_checkbox.SetToolTip(str(current_settings.get('ANTI_DOS')[1]).lower())
        if current_settings.get('ANTI_DOS')[0] == 'ON':
            self.anti_dos_enable_checkbox.SetValue(True)
        self.anti_dos_enable_checkbox.AcceptsFocus()
        self.anti_dos_enable_checkbox.AcceptsFocusFromKeyboard()
        self.anti_dos_enable_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_antidos_enable)

        antidos_ports_label = wx.StaticText(self,-1,"Ports:",(5,40))
        self.antidos_ports_input = wx.TextCtrl(self,-1,current_settings.get('ANTI_DOS_PORTS')[0],(50,38))
        self.antidos_ports_input.SetToolTip(str(current_settings.get('ANTI_DOS_PORTS')[1]).lower())
        self.antidos_ports_input.AcceptsFocus()
        self.antidos_ports_input.AcceptsFocusFromKeyboard()
        self.antidos_ports_input.Bind(wx.EVT_TEXT,self.OnChange_antidos_ports)


        antidos_throttle_label = wx.StaticText(self,-1,"Throttle:",(5,70))
        self.antidos_throttle_input = wx.TextCtrl(self,-1,current_settings.get('ANTI_DOS_THROTTLE_CONNECTIONS')[0],(50,68))
        self.antidos_throttle_input.SetToolTip(str(current_settings.get('ANTI_DOS_THROTTLE_CONNECTIONS')[1]).lower())
        self.antidos_throttle_input.AcceptsFocus()
        self.antidos_throttle_input.AcceptsFocusFromKeyboard()
        self.antidos_throttle_input.Bind(wx.EVT_TEXT,self.OnChange_antidos_throttle)
        
        antidos_burst_label = wx.StaticText(self,-1,"Burst:",(5,100))
        self.antidos_burst_input = wx.TextCtrl(self,-1,current_settings.get('ANTI_DOS_LIMIT_BURST')[0],(50,98))
        self.antidos_burst_input.SetToolTip(str(current_settings.get('ANTI_DOS_LIMIT_BURST')[1]).lower())
        self.antidos_burst_input.AcceptsFocus()
        self.antidos_burst_input.AcceptsFocusFromKeyboard()
        self.antidos_burst_input.Bind(wx.EVT_TEXT,self.OnChange_antidos_burst)


    def OnChange_antidos_enable(self,e):
        self.OnUpdate_checkbox('ANTI_DOS',self.anti_dos_enable_checkbox.IsChecked())

    def OnChange_antidos_ports(self,e):
        self.OnUpdate_txtctrl('ANTI_DOS_PORTS',self.antidos_ports_input.GetValue())

    def OnChange_antidos_throttle(self,e):
        self.OnUpdate_txtctrl('ANTI_DOS_THROTTLE_CONNECTIONS',self.antidos_throttle_input.GetValue())

    def OnChange_antidos_burst(self,e):
        self.OnUpdate_txtctrl('ANTI_DOS_LIMIT_BURST',self.antidos_burst_input.GetValue())



# class FtpTab(wx.Panel,CustomControls):
#     """Creates window for settings related to FTP"""
#     def __init__(self, parent):
#         wx.Panel.__init__(self, parent)


class SystemTab(wx.Panel,CustomControls):
    """Creates window with system info."""
    def __init__(self, parent):
        
        wx.Panel.__init__(self, parent)
        interface= current_settings.get("BIND_INTERFACE")[0]
        apath = global_settings.get("APP_PATH")[0]
        hostos = global_settings.get("HOST_OS")
        build = global_settings.get("BUILD")[0]
        cpath = apath[0]
        build_label = wx.StaticText(self, -1, f"Artillery Ver: {build}", (15, 22))
        hostos_label = wx.StaticText(self, -1, f"OS: {hostos[0]} build: {hostos[1]}", (15, 42))
        installpath_label = wx.StaticText(self, -1, f"Install path: {apath}", (15, 62))
        iface_label = wx.StaticText(self, -1, f"Interface: {self.get_hostname()}", (15, 82))
        port_info = self.get_total_open_ports()
        total_ports = port_info[0]
        tcp_ports = port_info[1]
        udp_ports = port_info[2]
        banned_ips = self.get_total_banned_ips()
        total_ports_label = wx.StaticText(self,-1,total_ports,(15,102))
        tcp_ports_label = wx.StaticText(self,-1,tcp_ports,(15,122))
        udp_ports_label = wx.StaticText(self,-1,udp_ports,(15,142))
        total_banned_ips_label = wx.StaticText(self,-1,banned_ips,(15,162))
        logger.info(build_label.GetLabelText())
        logger.info(hostos_label.GetLabelText())
        logger.info(installpath_label.GetLabelText())
        logger.info(total_ports_label.GetLabelText())
        logger.info(tcp_ports_label.GetLabelText())
        logger.info(udp_ports_label.GetLabelText())
        logger.info(total_banned_ips_label.GetLabelText())

        if 'win32' in sys.platform:
            service_status = self.is_artillery_active()
            service_status_label = wx.StaticText(self,-1,service_status[2],(15,182))
            #logger.info(service_status_label.GetLabelText())




class FolderTab(wx.Panel,CustomControls):
    """creates window for foldr tab"""
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.folder_monitor_enable_checkbox = wx.CheckBox(self,-1,'Enable:    ',(0,10))
        self.folder_monitor_enable_checkbox.SetToolTip(str(current_settings.get('MONITOR')[1]).lower())
        self.folder_monitor_enable_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        if current_settings.get('MONITOR')[0] == 'ON':
            self.folder_monitor_enable_checkbox.SetValue(True)
        self.folder_monitor_enable_checkbox.AcceptsFocus()
        self.folder_monitor_enable_checkbox.AcceptsFocusFromKeyboard()
        self.folder_monitor_enable_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_folder_monitor_enable)

        folder_monitor_label = wx.StaticText(self,-1,"Folders:",(5,40))
        self.folder_monitor_input = wx.TextCtrl(self,-1,current_settings.get('MONITOR_FOLDERS')[0],(60,38),(175,20))
        self.folder_monitor_input.SetToolTip(str(current_settings.get('MONITOR_FOLDERS')[1]).lower())
        self.folder_monitor_input.AcceptsFocus()
        self.folder_monitor_input.AcceptsFocusFromKeyboard()
        self.folder_monitor_input.Bind(wx.EVT_TEXT,self.OnChange_monitor_folders)

        folder_exclude_label = wx.StaticText(self,-1,"Exclude:",(5,70))
        self.folder_exclude_input = wx.TextCtrl(self,-1,current_settings.get('EXCLUDE')[0],(60,68),(175,20))
        self.folder_exclude_input.SetToolTip(str(current_settings.get('EXCLUDE')[1]).lower())
        self.folder_exclude_input.AcceptsFocus()
        self.folder_exclude_input.AcceptsFocusFromKeyboard()
        self.folder_exclude_input.Bind(wx.EVT_TEXT,self.OnChange_exclude_folders)


        monitor_frequency_label = wx.StaticText(self,-1,"Freq:",(5,100))
        self.monitor_frquency_input = wx.TextCtrl(self,-1,current_settings.get('MONITOR_FREQUENCY')[0],(60,98),(40,20))
        self.monitor_frquency_input.SetToolTip(str(current_settings.get('MONITOR_FREQUENCY')[1]).lower())
        self.monitor_frquency_input.AcceptsFocus()
        self.monitor_frquency_input.AcceptsFocusFromKeyboard()
        self.monitor_frquency_input.Bind(wx.EVT_TEXT,self.OnChange_monitor_frequency)
        # will show on windows in this frame. on linux this
        #is in ssh\ftp\apache tab which is not used on win32
        if 'win32' in sys.platform:
            self.system_hardening_checkbox = wx.CheckBox(self,-1,"Harden:",(175,10))
            self.system_hardening_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
            self.system_hardening_checkbox.SetToolTip(str(current_settings.get('SYSTEM_HARDENING')[1]).lower())
            if current_settings.get('SYSTEM_HARDENING')[0] == 'ON':
                self.system_hardening_checkbox.SetValue(True)
            self.system_hardening_checkbox.AcceptsFocus()
            self.system_hardening_checkbox.AcceptsFocusFromKeyboard()
            self.system_hardening_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_system_hardening)

    def OnChange_folder_monitor_enable(self,e):
        self.OnUpdate_checkbox('MONITOR',self.folder_monitor_enable_checkbox.IsChecked())

    def OnChange_monitor_folders(self,e):
        self.OnUpdate_txtctrl('MONITOR_FOLDERS',self.folder_monitor_input.GetValue())

    def OnChange_monitor_frequency(self,e):
        self.OnUpdate_txtctrl('MONITOR_FREQUENCY',self.monitor_frquency_input.GetValue())

    def OnChange_exclude_folders(self,e):
        self.OnUpdate_txtctrl('EXCLUDE',self.folder_exclude_input.GetValue())

    if 'win32' in sys.platform:
        def OnChange_system_hardening(self,e):
            self.OnUpdate_checkbox('SYSTEM_HARDENING',self.system_hardening_checkbox.IsChecked())


class SshTab(wx.Panel,CustomControls):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.ssh_brute_monitor_enable_checkbox = wx.CheckBox(self,-1,'SSH Brute:',(0,10))
        self.ssh_brute_monitor_enable_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        self.ssh_brute_monitor_enable_checkbox.SetToolTip(str(current_settings.get('SSH_BRUTE_MONITOR')[1]).lower())
        if current_settings.get('SSH_BRUTE_MONITOR')[0] == 'ON':
            self.ssh_brute_monitor_enable_checkbox.SetValue(True)
        self.ssh_brute_monitor_enable_checkbox.AcceptsFocus()
        self.ssh_brute_monitor_enable_checkbox.AcceptsFocusFromKeyboard()
        self.ssh_brute_monitor_enable_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_ssh_monitor_enabled)

        self.ftp_brute_monitorenable_checkbox = wx.CheckBox(self,-1,"FTP Brute:",(225,10))
        self.ftp_brute_monitorenable_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        self.ftp_brute_monitorenable_checkbox.SetToolTip(str(current_settings.get('FTP_BRUTE_MONITOR')[1]).lower())
        if current_settings.get('FTP_BRUTE_MONITOR')[0] == 'ON':
            self.ftp_brute_monitorenable_checkbox.SetValue(True)
        self.ftp_brute_monitorenable_checkbox.AcceptsFocus()
        self.ftp_brute_monitorenable_checkbox.AcceptsFocusFromKeyboard()
        self.ftp_brute_monitorenable_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_ftp_monitor_enabled)

        ssh_brute_attempts_label = wx.StaticText(self,-1,"SSH Limit:",(5,40))
        self.ssh_brute_attempts_input = wx.TextCtrl(self,-1,current_settings.get('SSH_BRUTE_ATTEMPTS')[0],(65,38),(25,20))
        self.ssh_brute_attempts_input.SetToolTip(str(current_settings.get('SSH_BRUTE_ATTEMPTS')[1]).lower())
        self.ssh_brute_attempts_input.AcceptsFocus()
        self.ssh_brute_attempts_input.AcceptsFocusFromKeyboard()
        self.ssh_brute_attempts_input.Bind(wx.EVT_TEXT,self.OnChange_ssh_brute_attempts)

        ftp_brute_attempts_label = wx.StaticText(self,-1,"FTP Limit:",(231,40))
        self.ftp_brute_attempts_input = wx.TextCtrl(self,-1,current_settings.get('FTP_BRUTE_ATTEMPTS')[0],(288,38),(25,20))
        self.ftp_brute_attempts_input.SetToolTip(str(current_settings.get('FTP_BRUTE_ATTEMPTS')[1]).lower())
        self.ftp_brute_attempts_input.AcceptsFocus()
        self.ftp_brute_attempts_input.AcceptsFocusFromKeyboard()
        self.ftp_brute_attempts_input.Bind(wx.EVT_TEXT,self.OnChange_ftp_brute_attempts)

        self.ssh_port_check_checkbox = wx.CheckBox(self,-1,'SSH port check:',(100,10))
        self.ssh_port_check_checkbox.SetToolTip(str(current_settings.get('SSH_DEFAULT_PORT_CHECK')[1]).lower())
        self.ssh_port_check_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        if current_settings.get('SSH_DEFAULT_PORT_CHECK')[0] == 'ON':
            self.ssh_port_check_checkbox.SetValue(True)
        self.ssh_port_check_checkbox.AcceptsFocus()
        self.ssh_port_check_checkbox.AcceptsFocusFromKeyboard()
        self.ssh_port_check_checkbox.Bind(wx.EVT_TEXT,self.OnChange_ssh_port_check)

        self.ssh_root_check_checkbox = wx.CheckBox(self,-1,'SSH root check:',(100,40))
        self.ssh_root_check_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        self.ssh_root_check_checkbox.SetToolTip(str(current_settings.get('ROOT_CHECK')[1]).lower())
        if current_settings.get('ROOT_CHECK')[0] == 'ON':
            self.ssh_root_check_checkbox.SetValue(True)
        self.ssh_root_check_checkbox.AcceptsFocus()
        self.ssh_root_check_checkbox.AcceptsFocusFromKeyboard()
        self.ssh_root_check_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_ssh_root_check)

        self.apache_monitor_checkbox = wx.CheckBox(self,-1,"Apache:    ",(0,70))
        self.apache_monitor_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        self.apache_monitor_checkbox.SetToolTip(str(current_settings.get('APACHE_MONITOR')[1]).lower())
        if current_settings.get('APACHE_MONITOR')[0] == 'ON':
            self.apache_monitor_checkbox.SetValue(True)
        self.apache_monitor_checkbox.AcceptsFocus()
        self.apache_monitor_checkbox.AcceptsFocusFromKeyboard()
        self.apache_monitor_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_apache_monitor)
        apache_access_label = wx.StaticText(self,-1,"access:",(5,92))
        self.apache_acces_log_input = wx.TextCtrl(self,-1,current_settings.get('ACCESS_LOG')[0],(63,90),(175,20))
        self.apache_acces_log_input.SetToolTip(str(current_settings.get('ACCESS_LOG')[1]).lower())
        self.apache_acces_log_input.AcceptsFocus()
        self.apache_acces_log_input.AcceptsFocusFromKeyboard()
        self.apache_acces_log_input.Bind(wx.EVT_TEXT,self.OnChange_access_log)


        apache_error_label = wx.StaticText(self,-1,"error:",(5,118))
        self.apache_error_log_input = wx.TextCtrl(self,-1,current_settings.get('ERROR_LOG')[0],(63,120),(175,20))
        self.apache_error_log_input.SetToolTip(str(current_settings.get('ERROR_LOG')[1]).lower())
        self.apache_error_log_input.AcceptsFocus()
        self.apache_error_log_input.AcceptsFocusFromKeyboard()
        self.apache_error_log_input.Bind(wx.EVT_TEXT,self.OnChange_error_log)

        self.system_hardening_checkbox = wx.CheckBox(self,-1,"Harden:",(255,120))
        self.system_hardening_checkbox.SetWindowStyle(wx.ALIGN_RIGHT)
        self.system_hardening_checkbox.SetToolTip(str(current_settings.get('SYSTEM_HARDENING')[1]).lower())
        if current_settings.get('SYSTEM_HARDENING')[0] == 'ON':
            self.system_hardening_checkbox.SetValue(True)
        self.system_hardening_checkbox.AcceptsFocus()
        self.system_hardening_checkbox.AcceptsFocusFromKeyboard()
        self.system_hardening_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_system_hardening)

    def OnChange_ssh_monitor_enabled(self,e):
        self.OnUpdate_checkbox('SSH_BRUTE_MONITOR',self.ssh_brute_monitor_enable_checkbox.IsChecked())
    
    def OnChange_ssh_brute_attempts(self,e):
        self.OnUpdate_txtctrl('SSH_BRUTE_ATTEMPTS',self.ssh_brute_attempts_input.GetValue())

    def OnChange_ftp_monitor_enabled(self,e):
        self.OnUpdate_checkbox('FTP_BRUTE_MONITOR',self.ftp_brute_monitorenable_checkbox.IsChecked())

    def OnChange_ftp_brute_attempts(self,e):
        self.OnUpdate_txtctrl('FTP_BRUTE_ATTEMPTS',self.ftp_brute_attempts_input.GetValue())

    def OnChange_ssh_port_check(self,e):
        self.OnUpdate_checkbox('SSH_DEFAULT_PORT_CHECK',self.ssh_port_check_checkbox.IsChecked())

    def OnChange_ssh_root_check(self,e):
        self.OnUpdate_checkbox('ROOT_CHECK',self.ssh_root_check_checkbox.IsChecked())

    def OnChange_apache_monitor(self,e):
        self.OnUpdate_checkbox('APACHE_MONITOR',self.apache_monitor_checkbox.IsChecked())

    def OnChange_access_log(self,e):
        self.OnUpdate_txtctrl('ACCESS_LOG',self.apache_acces_log_input.GetValue())

    def OnChange_error_log(self,e):
        self.OnUpdate_txtctrl('ERROR_LOG',self.apache_error_log_input.GetValue())

    def OnChange_system_hardening(self,e):
        self.OnUpdate_checkbox('SYSTEM_HARDENING',self.system_hardening_checkbox.IsChecked())


class MonitorTab(wx.Panel,CustomControls):
    """Creates window for settings related to file monitor"""
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        monitorpanel = wx.Notebook(self)
        dos = AntiDosTab(monitorpanel)
        folder = FolderTab(monitorpanel)
        ssh = SshTab(monitorpanel)
        monitorpanel.AddPage(dos, "Anti-Dos")
        monitorpanel.AddPage(folder, "Folder")
        monitorpanel.AddPage(ssh, "Ftp\Ssh\Apache")
        sizer = wx.BoxSizer()
        sizer.Add(monitorpanel, 1, wx.EXPAND | wx.ALL, 0)
        self.SetSizer(sizer)


class UpdateTab(wx.Panel,CustomControls):
    """Creates window for settings related to updates"""
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.updates_checkbox =wx.CheckBox(self, -1,'Enable:        ', (0, 10))
        self.updates_checkbox.SetWindowStyleFlag(wx.ALIGN_RIGHT)
        if current_settings.get('AUTO_UPDATE')[0] == 'ON':
            self.updates_checkbox.SetValue(True)
        self.updates_checkbox.SetToolTip(str(current_settings.get('AUTO_UPDATE')[1]).lower())
        self.updates_checkbox.AcceptsFocus()
        self.updates_checkbox.AcceptsFocusFromKeyboard()
        self.updates_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_update_enable)
        if 'win32' in sys.platform:
            update_location_label = wx.StaticText(self, -1, "Location:", (5, 40))
            self.update_location_input = wx.TextCtrl(self,-1,current_settings.get('UPDATE_LOCATION')[0],(70,38),(100,20))
            self.update_location_input.SetToolTip(str(current_settings.get('UPDATE_LOCATION')[1]).lower())
            self.update_location_input.AcceptsFocus()
            self.update_location_input.AcceptsFocusFromKeyboard()
            self.update_location_input.Bind(wx.EVT_TEXT,self.OnChange_update_location)
            update_frequency_label =update_location_label = wx.StaticText(self, -1, "Frequency:", (5, 70))
            self.update_frequency_input = wx.TextCtrl(self,-1,current_settings.get('UPDATE_FREQUENCY')[0],(70,68),(50,20))



    def OnChange_update_enable(self,e):
        self.OnUpdate_checkbox('AUTO_UPDATE',self.updates_checkbox.IsChecked())
    
    if 'win32' in sys.platform:
        def OnChange_update_location(self,e):
            self.OnUpdate_txtctrl('UPDATE_LOCATION',self.update_location_input.GetValue())

        def OnChange_update_frequency(self,e):
            self.OnChange_update_location('UPDATE_FREQUENCY',self.update_frequency_input.GetValue())


class ServicesTab(wx.Panel):
    """Creates window for settings related to services"""
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        servicepanel = wx.Notebook(self)
        monitor = MonitorTab(servicepanel)
        updates = UpdateTab(servicepanel)
        threat = ThreatTab(servicepanel)
        servicepanel.AddPage(monitor, "Monitor")
        servicepanel.AddPage(updates, "Updates")
        servicepanel.AddPage(threat, "ThreatFeed")
        sizer = wx.BoxSizer()
        sizer.Add(servicepanel, 1, wx.EXPAND | wx.ALL, 0)
        self.SetSizer(sizer)


class LoggingTab(wx.Panel):
    """Creates window for logging tabs"""
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        nb1 = wx.Notebook(self)
        email = EmailTab(nb1)
        syslog = SysLogTab(nb1)
        nb1.AddPage(email, "Email")
        nb1.AddPage(syslog, "Syslog")
        sizer = wx.BoxSizer()
        sizer.Add(nb1, 1, wx.EXPAND | wx.ALL, 0)
        self.SetSizer(sizer)


class HoneypotTab(wx.Panel,CustomControls):
    """Creates window for honeypot tab"""
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.get_bindaddress = current_settings.get('BIND_INTERFACE')[0]
        self.interface_choice = self.get_interfaces()
        active_nic = self.interface_choice[2]
        self.honeypot_checkbox= wx.CheckBox(self,-1,"Enable:",(0,10))
        self.honeypot_checkbox.SetWindowStyleFlag(wx.ALIGN_RIGHT)
        if current_settings.get("ENABLE_HONEYPOT")[0] == 'ON':
            self.honeypot_checkbox.SetValue(True)
        self.honeypot_checkbox.SetToolTip(str(current_settings.get('ENABLE_HONEYPOT')[1]).lower())
        self.honeypot_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_enable_honeypot)
        #interface selection drop-down
        iface_choice_label = wx.StaticText(self, -1, "Interface:", (70, 10))
        self.iface_choice = wx.Choice(self, wx.ID_ANY, (125, 8), wx.DefaultSize, self.interface_choice[0], 0,)
        # given the chance that the wrong ip is in config file catch the error and warn
        #but continue
        try:
            self.iface_choice.SetSelection(int(active_nic[0]))
        except IndexError as e:
            #just set the value to 0
            self.iface_choice.SetSelection(int(0))
            #and give them a msgbox warning
            msgbox = wx.MessageDialog(self,"The value in config file is diferrent then default nic please make sure it is the proper value",caption="Mismatched nic values",style=wx.OK, pos=wx.DefaultPosition)
            get_status = msgbox.ShowModal()
            if get_status == wx.ID_OK:
                logger.info("An exception occured durung nic detection. please make sure the ip address in config file is the right one in use.")
                msgbox.Destroy()
        self.iface_choice.SetToolTip(str(current_settings.get('BIND_INTERFACE')[1]).lower())
        self.iface_choice.AcceptsFocus()
        self.iface_choice.AcceptsFocusFromKeyboard()
        self.iface_choice.Bind(wx.EVT_CHOICE,self.OnChange_adapter)
        #auto accept checkbox
        self.autoaccept_checkbox = wx.CheckBox(self, -1, "Auto-Accept: ", (200, 45))
        if current_settings.get('HONEYPOT_AUTOACCEPT')[0] == 'ON':
            self.autoaccept_checkbox.SetValue(True)
        self.autoaccept_checkbox.SetWindowStyleFlag(wx.ALIGN_RIGHT)
        self.autoaccept_checkbox.SetToolTip(str(current_settings.get('HONEYPOT_AUTOACCEPT')[1]).lower())
        self.autoaccept_checkbox.AcceptsFocus()
        self.autoaccept_checkbox.AcceptsFocusFromKeyboard()
        self.autoaccept_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_autoaccept)
        #ban class c checkbox
        self.ban_classC_checkbox = wx.CheckBox(self, -1, "Ban Class C:   ", (200, 80))
        if current_settings.get('HONEYPOT_BAN_CLASSC')[0] == 'ON':
            self.ban_classC_checkbox.SetValue(True)
        self.ban_classC_checkbox.SetWindowStyleFlag(wx.ALIGN_RIGHT)
        self.ban_classC_checkbox.SetToolTip(str(current_settings.get('HONEYPOT_BAN_CLASSC')[1]).lower())
        self.ban_classC_checkbox.AcceptsFocus()
        self.ban_classC_checkbox.AcceptsFocusFromKeyboard()
        self.ban_classC_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_banclassc)
        #honeypot ban checkbox
        self.honeypot_ban_checkbox = wx.CheckBox(self, -1, "AutoBan:        ", (200, 115))
        if current_settings.get('HONEYPOT_BAN')[0] == 'ON':
            self.honeypot_ban_checkbox.SetValue(True)
        self.honeypot_ban_checkbox.SetWindowStyleFlag(wx.ALIGN_RIGHT)
        self.honeypot_ban_checkbox.SetToolTip(str(current_settings.get('HONEYPOT_BAN')[1]).lower())
        self.honeypot_ban_checkbox.AcceptsFocus()
        self.honeypot_ban_checkbox.AcceptsFocusFromKeyboard()
        self.honeypot_ban_checkbox.Bind(wx.EVT_CHECKBOX,self.OnChange_autoban)
        #tcp ports text input
        TCP_ports_label = wx.StaticText(self, -1, "TCP Ports:", (5, 50))
        self.TCP_ports_input = wx.TextCtrl(self,-1, current_settings.get('TCPPORTS')[0], (65, 45))
        self.TCP_ports_input.SetToolTip(str(current_settings.get('TCPPORTS')[1]).lower())
        self.TCP_ports_input.AcceptsFocus()
        self.TCP_ports_input.AcceptsFocusFromKeyboard()
        self.TCP_ports_input.Bind(wx.EVT_TEXT,self.OnChange_tcpports)
        #UDP ports text input
        UDP_ports_label = wx.StaticText(self, -1, "UDP Ports:", (5,80))
        self.UDP_ports_input = wx.TextCtrl(self, -1, current_settings.get('UDPPORTS')[0], (65, 78))
        self.UDP_ports_input.AcceptsFocus()
        self.UDP_ports_input.AcceptsFocusFromKeyboard()
        self.UDP_ports_input.SetToolTip(str(current_settings.get('UDPPORTS')[1]).lower())
        self.UDP_ports_input.Bind(wx.EVT_TEXT,self.OnChange_udpports)
        #
        banlog_prefix_label = wx.StaticText(self, -1, "Prefix:", (5,112))
        self.banlog_prefix_input = wx.TextCtrl(self,-1,current_settings.get('HONEYPOT_BAN_LOG_PREFIX')[0],(65,110))
        self.banlog_prefix_input.SetToolTip(str(current_settings.get('HONEYPOT_BAN_LOG_PREFIX')[1]).lower())
        self.banlog_prefix_input.AcceptsFocus()
        self.banlog_prefix_input.AcceptsFocusFromKeyboard()
        self.banlog_prefix_input.Bind(wx.EVT_TEXT,self.OnChange_banlog_prefix)
        #
        whitelist_label = wx.StaticText(self,-1,"Whitelist:",(5,150))
        self.whitelist_input = wx.TextCtrl(self,-1,current_settings.get('WHITELIST_IP')[0],(65,145))
        self.whitelist_input.SetToolTip(str(current_settings.get('WHITELIST_IP')[1]).lower())
        self.whitelist_input.AcceptsFocus()
        self.whitelist_input.AcceptsFocusFromKeyboard()
        self.whitelist_input.Bind(wx.EVT_TEXT,self.OnChange_whitelist)
    

    #all funcs below update there associated values according to input
    #update functions come from CustomControls class
    def OnChange_enable_honeypot(self,e):
        self.OnUpdate_checkbox("ENABLE_HONEYPOT",self.honeypot_checkbox.IsChecked())

    def OnChange_autoban(self,e):
        self.OnUpdate_checkbox("HONEYPOT_BAN",self.autoaccept_checkbox.IsChecked())
    
    def OnChange_udpports(self,e):
        self.OnUpdate_txtctrl("UDPPORTS",self.UDP_ports_input.GetValue())
    
    def OnChange_tcpports(self,e):
        self.OnUpdate_txtctrl("TCPPORTS",self.TCP_ports_input.GetValue())

    def OnChange_banlog_prefix(self,e):
        self.OnUpdate_txtctrl("HONEYPOT_BAN_LOG_PREFIX",self.banlog_prefix_input.GetValue())

    def OnChange_whitelist(self,e):
        self.OnUpdate_txtctrl("WHITELIST_IP",self.banlog_prefix_input.GetValue())

    def OnChange_banclassc(self,e):
        self.OnUpdate_checkbox("HONEYPOT_BAN_CLASSC",self.ban_classC_checkbox.IsChecked())
        

    def OnChange_autoaccept(self,e):
        if 'win32' in sys.platform:
            logger.info("HONEYPOT_AUTOACCEPT Flag is only supported on linux")
            return
        else:
            self.OnUpdate_checkbox("HONEYPOT_AUTOACCEPT",self.autoaccept_checkbox.IsChecked())
            return


    def OnChange_adapter(self,cs):
        """
        Keeps track of current selection of interface choice
        drop-down menu and updates value on change.
        """
        key = "BIND_INTERFACE"
        value = self.iface_choice.GetCurrentSelection()
        idx = print(str(value))
        #get the values from our nicmap
        name = self.interface_choice[0]
        address = self.interface_choice[1]
        #the friendlyname
        interfacename = name[value]
        #the actual ip
        interfaceip = address[interfacename][0]
        #update dict with values
        self.OnUpdate_txtctrl(key,interfaceip)
    
    def get_default_nic(self,gw,inf):
        """
        returns true if ips are in same network as the default gateway
        """
        a = ip_network(gw, strict = False).network_address 
        b = ip_network(inf, strict = False).network_address 
        
        
       
        #logger.info(f"{a} {b}")
        if(a == b) : 
            
            return True
        else : 
            return False
    
    def get_interfaces(self) -> tuple:
        """
        Returns a list of avalible interfaces by name for choice selection box.
        As well as generating a dict containing name to ip mappings for use with choice
        control concerning picking entries from control menu and making config changes.

        It will also asign active nic to choice control by comparing gateway to nic mapping
        and BIND_ADDRESS from config to determine correct adapter at runtime
        """
        #mapping of friendly name to ipaddress
        nic_map = {}
        #list of friendly names passed to choice function
        nic_list = []
        #list of guid number of all nics
        nic_guid = []
        #list of all detected ips
        nic_ips = []
        #list of lists of all nic values
        nic_values = []
        #returns the guid number of all nics
        inter = netifaces.interfaces()
        #returns the friendly names as seen in windows of all nics

        interfaces = psutil.net_if_addrs()
        logger.info("Grabbing nic info...")
        #Create initial dict with interface names
        for name in interfaces.keys():
            nic_list.append(name)
            nic_map[name] = ""
        #create a list of lists to isolate ip address info
        for value in interfaces.values():
            nic_values.append(value)
        #read all the lists and add ips detected to a new list
        for item in nic_values:
            value = item[1][1]
            nic_ips.append(value)
        for item in inter:
            nic_guid.append(item)
        #create our final dict of nic to ip mapping
        for key in nic_map.keys():
            #remove the first entry on every run
            ip = nic_ips.pop(0)
            guid = nic_guid.pop(0)
            nic_map[key] = [ip,guid]
        #get the default gateway
        gateway = netifaces.gateways()
        active_nic = []
        bind_address = self.get_bindaddress
        if len(gateway) == 0:
            #msgbox here?
            logger.info("no gateway was detected")
            active_nic.append(0)
        else:
            
            ipv4_value = gateway.get('default').get(2)
            #ipv6_value= gateway.get('default').get(23)
            logger.info(f"Nic GUID value: {ipv4_value[1]}")
            logger.info(f"IPv4 Nic address: {self.get_hostname()}")
            logger.info(f"IPv4 Gateway address: {ipv4_value[0]}")
            #try:
            #    logger.info(f"IPv6 Gateway address: {ipv6_value[0]}")
            #except None as err:
            #    logger.info(f"No IPv6 address was found is it enabled?")


            #now get the value of actual nic being used 
            #for honeypot if any to pass along to choice func
            #by comparing bind_address to active nics to see if they 
            #are the same and pass the index # along??????
            #set the counter to negative one to make 
            # sure we get the right index number of adpapter
            counter= -1
            for value in nic_map.values():
                counter+=1
                result = self.get_default_nic(str(bind_address),str(value[0]))
                if result == True:
                    new_counter = counter
                    active_nic.append(str(new_counter))
        
        return nic_list,nic_map,active_nic
        


class MainServicesFrame(wx.Frame):
    """main window where all frames come together"""
    def __init__(self):
        #set the main frame to a static size
        wx.Frame.__init__(self, None, title="Artillery Settings Manager", size=wx.Size(375, 275), style=wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
        self.SetIcon(wx.Icon('.//src//icons//settings_icon.ico', wx.BITMAP_TYPE_ICO))
        # Create a panel and add a nbs to it.
        panel = wx.Panel(self,-1,pos=wx.DefaultPosition,size=wx.DefaultSize,style=wx.TAB_TRAVERSAL,name="MainPanel")
        nb = wx.Notebook(panel)

        # Create the tab windows
        system = SystemTab(nb)
        services = ServicesTab(nb)
        logging = LoggingTab(nb)
        honeypot = HoneypotTab(nb)
        # Add the tabs to window and name them.
        nb.AddPage(system, "System")
        nb.AddPage(services, "Services")
        nb.AddPage(logging, "Logging")
        nb.AddPage(honeypot, "Honeypot")
        # put noteboook in a sizer to create the layout
        sizer = wx.BoxSizer()
        sizer.Add(nb, 1, wx.EXPAND)
        panel.SetSizer(sizer)
        self.Bind(wx.EVT_CLOSE, self.Onclose)

    def Onclose(self,event):
        """
        Checks to see if any settings were changed if True shows the user a message box
        making them aware of pending changes asks them if they want to apply them if YES
        it applies them and the exits. if NO it discards changes and then exits
        """
        if settings_changed == True:
            msgbox = wx.MessageDialog(self,"Changes have been made would you like to apply them now?",caption="Changes Detected",style=wx.YES|wx.NO, pos=wx.DefaultPosition)
            get_status = msgbox.ShowModal()
            if get_status == wx.ID_YES:
                update_config()
                logger.info(f"The following settings have been applied:  {settings_to_update}")
            elif get_status == wx.ID_NO:
                logger.info("You chose not to apply changes")
        #kill the app  
        self.Destroy()

if __name__ == "__main__":
    app = wx.App()
    MainServicesFrame().Show()
    app.MainLoop()
