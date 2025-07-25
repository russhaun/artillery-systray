#!/usr/bin/python
#
# this is the honeypot stuff
#
#

import _thread as thread
import socket
import time
import socketserver as SocketServer
import os
import random
import datetime
from src.core import *
import traceback
from src.email_handler import warn_the_good_guys
from src.config import tcp_ports, udp_ports, bind_interface, honeypot_ban_enabled, honeypot_autoaccept, log_message_alert, log_message_ban, exceptionlog


class TCPServer((SocketServer.ThreadingTCPServer)):
    """
    defines a basic tcp server with threading
    """
    def handle_error(self, request, client_address):
        write_console(f"client {client_address} had an error {str(request)}")

    request_queue_size = 10


class UDPServer((SocketServer.ThreadingUDPServer)):
    """
    defines a basic udp server with threading
    """
    #
    def handle_error(self, request, client_address):
        write_console(f"client {client_address} had an error {str(request)}")

    request_queue_size = 10


class UDPSocket((SocketServer.BaseRequestHandler)):
    '''creates a udp socket. all methods run in order setup(1), handle(2), finish(3).
    '''
    #
    def handle(self):
        '''takes data from attacker and does stuff. Then jumps to finish function'''
        #take info and do more stuff
        data = self.request[0].strip()
        skt = self.request[1]
        print(f"Data recieved: {data}")
        #skt.sendto(self.fake_string ,self.client_address)

    def setup(self):
        '''checks to see if ip is valid and not on whitelist.
        Gets some initial info about attacker and alerts
        on connection then jumps to handle function'''
        # fake_string = random number between 5 and 30,000 then os.urandom the
        # command back
        self.random_length_number = random.randint(5, 30000)
        self.fake_string = os.urandom(int(self.random_length_number))

        ip = str(self.client_address[0])
        if is_valid_ipv4(ip):
            if not is_whitelisted_ip(ip):
                #srv_ip = str(self.server.server_address[0])
                srv_port = str(self.server.server_address[1])
                write_console(f"connection from {ip} on udp port {srv_port}")

    def finish(self):
        '''Maybe get even more stuff and then
        get that mofo outta here and perform cleanup'''
        #print("gonna ban em")
        return


class TCPSocket((SocketServer.BaseRequestHandler)):
    '''creates a tcp socket. all methods run in order setup(1),handle(2),finish(3).
    for now handle and finish do nothing'''
    def handle(self):
        '''takes data from attacker and does stuff. Then jumps to finish function'''
        #take info and do stuff
        #try:
        #    write_log("Honeypot detected incoming connection from %s to tcp port %s" % (self.ip, self.server.server_address[1]))
        #    self.request.send(self.fake_string)
        #except Exception as e:
        #    write_console("Unable to send data to %s:%s" % (self.ip, str(self.server.server_address[1])))
        pass

    def setup(self):
        """
            checks to see if ip is valid and not on whitelist.
        Gets some initial info about attacker and alerts
        on connection then jumps to handle function
        """
        self.ip = self.client_address[0]
        self.data = self.request.recv(4096).strip()
        srv_ip = str(self.server.server_address[0])
        srv_port = str(self.server.server_address[1])
        length = random.randint(5, 30000)
        self.fake_string = os.urandom(int(length))

        # try the actual sending and banning
        try:
            ip = self.client_address[0]
            try:
                write_log("Honeypot detected incoming connection from %s to tcp port %s" % (ip, self.server.server_address[1]))
                self.request.send(self.fake_string)
            except Exception as e:
                write_console("Unable to send data to %s:%s" % (self.ip, str(self.server.server_address[1])))
            #    pass
            if is_valid_ipv4(self.ip):
                if not is_whitelisted_ip(self.ip):
                    now = str(datetime.datetime.today())
                    port = str(self.server.server_address[1])
                    subject = "%s [!] Artillery has detected an attack from the IP Address: %s" % (
                        now, self.ip)
                    alert = ""
                    message = log_message_alert
                    if honeypot_ban_enabled is True:
                        message = log_message_ban
                    message = message.replace("%time%", now)
                    message = message.replace("%ip%", self.ip)
                    message = message.replace("%port%", str(port))
                    alert = message
                    if "%" in message:
                        nrvars = message.count("%")
                        if nrvars == 1:
                            alert = message % (now)
                        elif nrvars == 2:
                            alert = message % (now, self.ip)
                        elif nrvars == 3:
                            alert = message % (now, self.ip, str(port))
                    #
                    warn_the_good_guys(subject, alert)
                    # close the socket
                    try:
                        self.request.close()
                    except:
                        pass

                    # if it isn't whitelisted and we are set to ban
                    ban(self.ip)
                else:
                    write_log(f"Ignore connection from {self.ip} to port {str(self.server.server_address[1])} whitelisted.")

        except Exception as e:
            emsg = traceback.format_exc()
            write_console(f"[!] Error detected. Printing: {str(e)}")
            write_console(emsg)
            write_log(emsg, 2)
            #log_exception(f"[!] Error detected. Printing: {str(e)}")
            #print("")

    def finish(self):
        pass
        # get that mofo outta here and perform cleanup
        # close the socket
        #try:
        #   self.request.close()
        #except:

        return


def open_sesame(porttype, port):
    """
    adds entries to iptables for posix platform
    """
    if honeypot_autoaccept:
        if is_posix():
            cmd = "iptables -D ARTILLERY -p %s --dport %s -j ACCEPT -w 3" % (porttype, port)
            execOScmd(cmd)
            cmd = "iptables -A ARTILLERY -p %s --dport %s -j ACCEPT -w 3" % (porttype, port)
            execOScmd(cmd)
            #write_log("Created iptables rule to accept incoming connection to %s %s" % (porttype, port))
        if is_windows():
            pass
#
#this is a temporary function to handle errors from check_open_port()
#will be removed in future


def log_exception(exception):
    """
    logs all server exceptions to artillery exceptions.log file
    """
    with open(exceptionlog, "a") as event:
        event.write(str(exception) + "\n")


def check_open_port(port, port_type, bind_interface):
    '''attempts to see if ports are open on local host.
        retuns True if open. False if closed '''
    if port_type == "TCP":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if port_type == "UDP":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#
    result = False
    try:
        sock.bind((bind_interface, int(port)))
        result = True
        #print(f"{port_type}: {port} is open")
    except socket.error as e:
        #print(f"{port_type}: {port} is closed")
        log_exception(f"{port_type} port: {port} creation failed with: {str(e)}. Please check the config file and make sure the port is not in use")
        result = False

    sock.close()
    return result


def listentcp_server(tcpport, bind_interface):
    '''Creates a basic TCP server based on TCPServer and TCPSocket classes'''
    if not tcpport == "":
        port = int(tcpport)
        #this will bind to all ips. localhost/0.0./and lan
        if bind_interface == "":
            #server = ThreadingTCPServer(ThreadingMixin, TCPServer(('', port), TCPSocket))
            server = TCPServer(('', port), TCPSocket)
        else:
            #this will only bind to given ip from config file
            #server = ThreadingTCPServer(ThreadingMixin, TCPServer((bind_interface, port), TCPSocket))
            server = TCPServer((bind_interface, port), TCPSocket)
        open_sesame("tcp", port)
        server.serve_forever()


def listenudp_server(udpport, bind_interface):
    '''Creates a basic UDP server based on UDPServer and UDPSocket classes'''
    if not udpport == "":
        port = int(udpport)
        #this will bind to all ips. localhost/0.0./and lan
        if bind_interface == "":
            server = UDPServer(('', port), UDPSocket)
        else:
            #this will only bind to given ip from config file
            server = UDPServer((bind_interface, port), UDPSocket)
        open_sesame("udp", port)
        server.serve_forever()


def main(tcpports, udpports, bind_interface):
    """
        main function that creates all servers from classes above.
        checks to see if ports are availible if not skips and
        sends alert/email after gathering all info/exceptions
        if ports were not used from config file.
    """
    # split tcpports into tuple
    open_tcp = []
    open_udp = []
    closed_tcp = []
    closed_udp = []
    tports = tcpports.split(",")
    for tport in tports:
        tport = tport.replace(" ", "")
        #if the ports not blank
        if tport != "":
            #check to see if port is in use
            port_availible = check_open_port(tport, "TCP", bind_interface)
            if port_availible is True:
                open_tcp.append(tport)
                #write_log(f"[*] Set up listener for tcp port {tport}")
                time.sleep(.5)
                #thread.start_new_thread(sniffer, (host,bind_interface,'TCP',tport))
                thread.start_new_thread(listentcp_server, (tport, bind_interface,))
            else:
                closed_tcp.append(tport)
    #
    # split into tuple
    uports = udpports.split(",")
    for uport in uports:
        uport = uport.replace(" ", "")
        if uport != "":
            #check to see if port is in use
            port_availible = check_open_port(uport, "UDP", bind_interface)
            if port_availible is True:
                open_udp.append(uport)
                #write_log(f"[*] Set up listener for udp port {uport}")
                time.sleep(.5)
                #thread.start_new_thread(sniffer, (host,bind_interface,'TCP', tport))
                thread.start_new_thread(listenudp_server, (uport, bind_interface,))
            else:
                closed_udp.append(uport)
    #
    #check to see if some ports were open/closed
    # during startup and report if so
    tcp_bind_success = False
    udp_bind_success = False
    tcp_bind_error = False
    udp_bind_error = False
    failed_tcp = 0
    failed_udp = 0
    success_tcp = 0
    success_udp = 0
    #if there are entries
    if len(open_udp) > 0:
        #set to true
        udp_bind_success = True
        #add num of ports to list
        success_udp += len(open_udp)
    if len(open_tcp) > 0:
        #set to true
        tcp_bind_success = True
        #add num of ports to list
        success_tcp += len(open_tcp)
    if len(closed_udp) > 0:
        #set error to true
        udp_bind_error = True
        #add num of ports to list
        failed_udp += len(closed_udp)
    if len(closed_tcp) > 0:
        tcp_bind_error = True
        failed_tcp += len(closed_tcp)
    #check if bind_error is set to true and set up msg for alert
    if tcp_bind_error or udp_bind_error is True:
        subject = " Artillery error - Unable to bind to some ports"
        if tcp_bind_error and udp_bind_error is True:
            bind_error = f"Artillery was unable to bind to {str(failed_tcp)} TCP port/ports: {str(closed_tcp)}.{str(failed_udp)} UDP port/ports: {str(closed_udp)} This could be due to an active port in use."
        if tcp_bind_error is True and udp_bind_error is False:
            bind_error = f"Artillery was unable to bind to {str(failed_tcp)} TCP port/ports: {str(closed_tcp)}. This could be due to an active port in use."
        if tcp_bind_error is False and udp_bind_error is True:
            bind_error = f"Artillery was unable to bind to {str(failed_udp)} UDP port/ports: {str(closed_udp)} This could be due to an active port in use."
        write_log(f"{bind_error}", 2)
        warn_the_good_guys(subject, bind_error)
        #clear exception log
        with open(exceptionlog, "r+") as log:
            log.truncate(0)
    if tcp_bind_success or udp_bind_success is True:
        subject = "Set up listener on some ports"
        if tcp_bind_success and udp_bind_success is True:
            message = f"{subject} Opened {str(success_tcp)} TCP ports and {str(success_udp)} UDP Ports"
        if tcp_bind_success is True and udp_bind_success is False:
            message = f"{subject} Opened {str(success_tcp)} TCP ports."
        if tcp_bind_success is False and udp_bind_success is True:
            message = f"{subject} Opened {str(success_udp)} UDP Ports."
        write_log(f"{message}", 0)
        write_log(f"TCP ports: {str(open_tcp)}", 0)
        write_log(f"UDP ports: {str(open_udp)}", 0)
        if is_posix():
            write_log(f"Created {success_tcp+success_udp} iptables rules to accept incoming connections", 0)
        #write_console(f"Created iptables rule to accept incoming connection for {success_tcp+success_udp} ports")


def start_honeypot():
    """
    starts main honeypot fuction
    """
    write_console("[*] Starting honeypot.")
    write_log("[*] Launching honeypot.")
    main(tcp_ports, udp_ports, bind_interface)
