#!/usr/bin/python
#
#
# Handles emails from the config. Delivers after X amount of time
#
#
import string
import smtplib
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
#from email.mime.base import MIMEBase
from email.mime.text import MIMEText
#from email import encoders
from src.core import *
from src.config import two_factor_pass, mail_time, check_interval, timer_enabled, email_enabled, alert_user, smtp_user, smtp_pwd, smtp_address, smtp_port, smtp_from
from . import globals
import random
import _thread as thread
# check how long to send the email
send_now_set = 1


def warn_the_good_guys(subject, alert):
    """
    Helper func to assist in sending emails.
    Determines if email alerts are enabled uses the timer if applicable.
    sends it if set to "ON".

    Note:
        as this is called from inside class from honeypot.py.
        it is called multiple times based on # of ports open. to stop pollution of actual email
        configure to write alerts to file and pick up all alerts at once on a timer maybe?
        and send one email with all alerts to reduce amount of individual emails
    """
    #sent = 0
    subject = gethostname() + " | " + subject
    # if TRUE and TRUE hold the alert for later delivery
    if email_enabled is True and timer_enabled is True:
        prep_email(alert + "\n")
    # if TRUE and False send the email now
    elif email_enabled is True and timer_enabled is False:
        #if sent == 0:
        send_mail(subject, alert)
    #if FALSE and FALSE emails disabled
    elif not email_enabled and not timer_enabled:
        pass
    #if FALSE and TRUE should never happen
    elif not email_enabled and timer_enabled:
        pass


def convert_time(sec):
    """
    converts time from sec to min. for printing HR times
    """
    sec_value = sec % (24 * 3600)
    hr_value = sec_value // 3600
    min = sec_value // 60
    sec_value %= 60
    #write_console(f"time from {sec} to min: {min}")
    return [str(min), str(hr_value)]


def send_mail(subject, text) -> None:
    """
    adds email username to mail func and calls it
    """
    mail(alert_user, subject, text)


def prep_email(alert):
    """
        Appends entries to email alerts file to be sent at later time.
    """
    if is_posix():
        # check if folder program_junk exists
        if not os.path.isdir("%s/src/program_junk" % globals.g_apppath):
            os.mkdir("%s/src/program_junk" % globals.g_apppath)
        # write the file out to program_junk
        filewrite = open(
            "%s/src/program_junk/email_alerts.log" % globals.g_apppath, "a")
    if is_windows():
        #open alerts file
        filewrite = open(f"{globals.g_apppath}\\src\\program_junk\\email_alerts.log", "a")
        #
    filewrite.write(alert + "\n")
    filewrite.close()


def id_generator(size=6, chars=string.ascii_uppercase + string.digits) -> str:
    """
    returns random id for use in email message id
    """
    return ''.join(random.choice(chars) for _ in range(size))


def mail(to, subject, text) -> None:
    """
        Sends an email based on config settings from a predefined template

    """
    msg = MIMEMultipart()
    msg['From'] = smtp_from
    msg['To'] = to
    msg['Date'] = formatdate(localtime=True)
    msg['Message-Id'] = "<" + id_generator(20) + "." + smtp_from + ">"
    msg['Subject'] = subject
    #msg['CC'] =
    #
    msg.attach(MIMEText(text))
    # prep the smtp server
    mailServer = smtplib.SMTP("%s" % (smtp_address), smtp_port)
    mailServer.ehlo()
    if not smtp_user == "":
        # tls support?
        mailServer.starttls()
        # some servers require ehlo again
        mailServer.ehlo()
        #write_console(smtp_user)
        #write_console(smtp_pwd)
        mailServer.login(smtp_user, smtp_pwd)
    # send the mail
    write_log("Sending email to %s: %s" % (to, subject))
    mailServer.sendmail(smtp_from, to, msg.as_string())
    mailServer.close()
    return


def check_alert():
    """
    handles loop for checking email for alerts based on email_timer setting in config file
    """
    # loop forever
    timer = convert_time(check_interval)
    write_console(f"[*] Email Timer set to trigger every {timer[0]} minutes")

    while 1:
        time.sleep(check_interval)
        mail_log_file = ""
        mail_old_log_file = ""
        if is_posix():
            mail_log_file = f"{globals.g_apppath}\\src\\program_junk\\email_alerts.log"
            mail_old_log_file = f"{globals.g_apppath}\\src\\program_junk\\email_alerts.old"
        if is_windows():
            mail_log_file = f"{globals.g_apppath}\\src\\program_junk\\email_alerts.log"
            mail_old_log_file = f"{globals.g_apppath}\\src\\program_junk\\email_alerts.old"
        # if the file is there, read it in then trigger email
        if os.path.isfile(mail_log_file):
            # read open the file to be sent
            fileopen = open(mail_log_file, "r")
            data = fileopen.read()
            host = socket.gethostname()
            msg = f"[!] {host}: Artillery has new notifications for you."
            send_mail(msg, data)
            fileopen.close()
            # save this for later just in case we need it
            shutil.move(mail_log_file, mail_old_log_file)
        #time.sleep(check_interval)


def check_alert_thread() -> None:
    """
        Starts a thread for checking email alerts if enabled.
    will only start if EMAIL_TIMER and EMAIL_ALERTS is on in config file.

    """
    write_log("[*] Starting thread to check for email alerts")
    write_console("[*] Starting thread to check for email alerts")
    thread.start_new_thread(check_alert, ())


def start_email_handler():
    """
        Checks to see if either EMAIL_ALERTS and EMAIL_TIMER return True from config file.
    if enabled grabs settings from config related to email and reads timer if set.
    if yes then starts check_alert_thread(). if not sends out right away
    """
    #if email_enabled is True:
    write_console("[*] Email alerts are enabled")
    if timer_enabled is True:
        write_console("[*] Email timer is enabled")
        check_alert_thread()
    else:
        write_console("[*] Email timer is disabled email will be sent immediatly could be alot of spam")
