################################################################################
#
#  Artillery - An active honeypotting tool and threat intelligence feed
#
# Written by Dave Kennedy (ReL1K) @HackingDave
#
# A Binary Defense Project (https://www.binarydefense.com) @Binary_Defense
#
################################################################################
#
import signal
import time
import sys
import os
import _thread as thread
from src.config import configfile, email_enabled, alertlog, banlist, check_config, appname, apppath, is_windows_os, is_posix_os, file_monitor_enabled, recycle_ips_enabled, threat_server_enabled, auto_update_enabled, anti_dos_enabled, honeypot_enabled, ssh_brute_monitor_enabled, source_feeds_enabled, harden_check, ftp_brute_monitor_enabled, threat_feed_enabled, apache_monitor_enabled
from src.pyuac import isUserAdmin, runAsAdmin
from src.core import write_console, write_log, globals, check_banlist_path, create_iptables_subset, update, pull_source_feeds, refresh_log, threat_server

#
if is_windows_os is True:
    from src.win_func import get_pid, get_title, get_os, current_version, freeze_check
    from src.event_log import write_windows_eventlog, info
#################################################################################


class MainWindow():
    """
        Main Class file for handling gathering of all options avalible to artillery
    and presenting to user. All project scripts get imported and are
    executed from this class

    """

    def __init__(self) -> None:
        """init some defauls for class"""
        self.windowname = "Artillery - Advanced Threat Detection"
        self.appname = appname
        self.apppath = apppath
        self.configfile = configfile
        self.logfile = alertlog
        self.banlist = banlist
        self.running_threads = []

    #
    #
    def run(self):
        """runs final class object with configured settings"""
        if is_windows_os is True:
            FILE_PATH = freeze_check()
            write_log(f"[*] Artillery is running from {FILE_PATH}")
            check_config()
            get_title()
            current_version()
            get_os()
            get_pid()
        if is_posix_os is True:
            check_config()
            #current_version()
            if not os.path.isdir(globals.g_apppath + "/database/"):
                os.makedirs(globals.g_apppath + "/database/")
            if not os.path.isfile(globals.g_apppath + "/database/temp.database"):
                filewrite = open(globals.g_apppath + "/database/temp.database", "w")
                filewrite.write("")
                filewrite.close()
        #
        self.load_services_as_thread()

    def kill_running_threads():
        """
        kills all running threads. used during shutdown to clean up active threads.
        """
        print("hey")

    def shutdown(self):
        """calls sys.exit() and closes software"""
        write_console("[!] Ctrl-C Detected! Closing down")
        write_log("[!] Ctrl-C Detected! Closing down")
        write_console("[!] Exiting Artillery... hack the gibson.")
        time.sleep(5)
        sys.exit()

    def load_services_as_thread(self):
        """
        Starts load_services() in a thread.
        """
        loadid = thread.start_new_thread(self.load_services, ())
        self.running_threads.append(loadid)

    def load_services(self) -> None:
        """
            Loads all availible services depending on config returned
        all values are retrieved from config.py where all config
        checks are performed. the use of start_new_thread() in the future
        will be removed in favor of the more current Thread availible in py3.
        """
        check_banlist_path()
        # if we are running posix then lets create a new iptables chain
        if is_posix_os is True:
            time.sleep(2)
            write_console("[*] Creating iptables entries, hold on.")
            create_iptables_subset()
            write_console("[*] iptables entries created.")
        #
        # update artillery
        if auto_update_enabled is True:
            thread.start_new_thread(update, ())
        #
        # start anti_dos
        if anti_dos_enabled is True:
            from src.anti_dos import start_anti_dos
            thread.start_new_thread(start_anti_dos, ())
        #
        # spawn honeypot
        if honeypot_enabled is True:
            from src.honeypot import start_honeypot
            thread.start_new_thread(start_honeypot, ())
        #
        #start ssh monitor
        if ssh_brute_monitor_enabled is True:
            from src.ssh_monitor import start_ssh_monitor
            thread.start_new_thread(start_ssh_monitor, ())
        #
        #start ftp monitor
        if ftp_brute_monitor_enabled is True:
            from src.ftp_monitor import start_ftp_monitor
            thread.start_new_thread(start_ftp_monitor, ())
        #
        #start monitor engine
        if file_monitor_enabled is True:
            if is_posix_os is True:
                from src.monitor import start_monitor
                thread.start_new_thread(start_monitor, ())
            #
            if is_windows_os is True:
                from src.monitor import watch_folders
                thread.start_new_thread(watch_folders, ())
        #
        # check system hardening
        if harden_check is True:
            from src.harden import hardening_checks
            thread.start_new_thread(hardening_checks, ())
        #
        # start the email handler
        if email_enabled is True:
            from src.email_handler import start_email_handler
            thread.start_new_thread(start_email_handler, ())
        #
        # check to see if we are a threat server or not
        if threat_server_enabled is True:
            thread.start_new_thread(threat_server, ())
        #
        # recycle IP addresses if enabled
        if recycle_ips_enabled is True:
            thread.start_new_thread(refresh_log, ())
        #
        # start apache monitor
        if apache_monitor_enabled is True:
            from src.apache_monitor import start_apache_log_monitor
            thread.start_new_thread(start_apache_log_monitor, ())
        #
        # pull additional source feeds from external parties other than artillery
        if threat_feed_enabled or source_feeds_enabled is True:
            thread.start_new_thread(pull_source_feeds, ())
        #
        #
        write_console("[*] Console logging enabled. \n[*] Use Ctrl+C to exit.")
        write_log("[*] Artillery has started")
        if is_windows_os is True:
            write_windows_eventlog('Artillery', 100, info, False, None)
        #
        #print(self.running_threads)
        return


def master_timer():
    """This function sleeps for the max that time.sleep() allows in a loop
    that calculates out to around a little over 1yr.

    the math is this:

           1yr = 31536000 secs.
           py3 max = 4294967 secs.

           4294967 x 8 = 34359736 secs

    so i added 1 to the total count to give me the yr i needed at 9 it quits

    """
    count_max = 9
    current_count = 0
    #4294967
    timer = [4294967]
    while current_count is not count_max:
        current_count += 1
        time.sleep(timer[0])


def admin_check(app: str) -> None:
    """
        Used with Mainwindow class. admin/root check for windows/linux platforms.
    takes app as string to use for calling app.run() if admin is True
    """
    if is_windows_os is True:
        if not isUserAdmin():
            runAsAdmin(cmdLine=None, wait=False)
            sys.exit(1)
        if isUserAdmin():
            app.run()
#
    if is_posix_os is True:
        # Check to see if we are root
        try:  # try and delete folder
            if os.path.isdir("/var/artillery_check_root"):
                os.rmdir('/var/artillery_check_root')
        #if not thow error and quit
        except OSError as err:
            if (err.errno == errno.EACCES or err.errno == errno.EPERM):
                print("[*] You must be root to run this script!\r\n")
                sys.exit(1)
        else:
            #if root run app
            app.run()


if __name__ == "__main__":
    RUNNING = True

    def sig_handler(signum, frame):
        """
        handles ctrl-c events to exit software.
        """
        global RUNNING
        RUNNING = False
        app.shutdown()
    #
    #define signal to catch ctrl-c event
    signal.signal(signal.SIGINT, sig_handler)
    #
    while RUNNING:
        #load the class
        app = MainWindow()
        #check admin status. i know this is wrong. check is in class
        #im passing the actual object MainWindow here. but it works
        #because i force a string object in call with types
        admin_check(app)
        #sleep for a long f-ing time approx 4.2 mil secs about 49.7 days in a loop
        #for a yr
        master_timer()
