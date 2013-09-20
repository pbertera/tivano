#!/usr/bin/python
# vi:si:et:sw=4:sts=4:ts=4
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-

import struct
import socket
import logging
import logging.handlers
import sys
import os
import re
import ConfigParser

from string import Template

class InvalidRegexError(Exception): pass

class Logger:
    def __init__(self, name, level="info"):
        logging.handlers.raiseExceptions = True

        self.logger = logging.getLogger(name)
        self.log_handler = logging.StreamHandler()
        self.formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        self.log_handler.setFormatter(self.formatter)
        self.logger.addHandler(self.log_handler)
        if level == "info":
            self.logger.setLevel(logging.INFO)
        if level == "debug":
            self.logger.setLevel(logging.DEBUG)

    def change_handler(self, new_handler):
        new_handler.setFormatter(self.formatter)
        self.logger.removeHandler(self.log_handler)
        self.logger.addHandler(new_handler)

    def set_level(self,level):
        if level == "info":
            self.logger.setLevel(logging.INFO)
        if level == "debug":
            self.logger.setLevel(logging.DEBUG)

    def error(self, message=None):
        if message:
            self.logger.error(message)
        pass

    unsupportedSIPVersion = error
    unsupportedSIPTransport = error
    sendDataError = error
    systemError = error
    configError = error
    errorMessage = error

    def debug(self, message=None):
        if message:
            self.logger.debug(message)
        pass

    debugMessage = debug

    def info(self, message=None):
        if message:
            self.logger.info(message)
        pass
    
    infoMessage = info

# errors
class SocketOptionError(Exception): pass
class CreateSocketError(Exception): pass
class BindSocketError(Exception): pass
class InvalidRegexError(Exception): pass

class SettingsParser:
    def __init__(self, config_file, logger=None):
        
        if not logger:
            self.logger = Logger("SettingsParser")
    
        self.logger = logger
        self.config_file = config_file
        self.config = ConfigParser.RawConfigParser()
        # Make case sensitive parser
        self.config.optionxform = str
        self.config.read(self.config_file)
        
        self.common_config = {}
    
    def get_config(self):
        return self.config

    def parse_main(self):
        """
        This function parse the configuration file for
        - debug: "True", "False"
        - local_ip: "default", "xxx.xxx.xxx.xxx", "eth0"
        - log_file: "/var/log/file.log", "syslog://" 
        - daemon: "True", "False"
        - pid_file: "/var/run/test.pid"
        """
        try:
            self.common_config["debug"] = self.config.get('main', 'debug')
        except ConfigParser.NoOptionError:
            self.common_config["debug"] = "FALSE"
    
        try:
            conf_local_ip = self.config.get('main', 'local_ip')
            if is_valid_ipv4_address(conf_local_ip):
                self.common_config["local_ip"] = conf_local_ip
            
            elif conf_local_ip == "default": #if loca_if == "default" try to reach google.com
                try:
                    self.common_config["local_ip"] = get_ip_address()
                except Exception, e:
                    self.logger.configError("cannot discover local ip address: %s" % e)
                    sys.exit(1)

            else: #network interface name
                try:
                    self.common_config["local_ip"] = get_ip_address_ifname(conf_local_ip)
                except Exception, e:
                    self.logger.configError("cannot determine ip address of %s interface: %s" % (conf_local_ip, e))
                    sys.exit(1)

        except ConfigParser.NoOptionError:    
            self.logger.configError("Missing mandatory parameters in config file, bailing out!")
            sys.exit(1)

        try:
            log_file = self.common_config["log_file"] = self.config.get('main', 'log_file')        
            if log_file.startswith("syslog"):
                try:
                    syslog_host = log_file.split(":")[1]
                except IndexError:
                    syslog_host = 'localhost'
                try:
                    syslog_port = int(log_file.split(":")[2])
                except IndexError:
                    syslog_port = 514
                try:
                    syslog_facility = log_file.split(":")[3]
                except IndexError:
                    syslog_facility = logging.handlers.SysLogHandler.LOG_USER
                self.logger.debugMessage("Logging to syslog (host: %s, port: %s, facility: %s)" % ((syslog_host, syslog_port, syslog_facility)))
                self.common_config["conf_log_handler"] = logging.handlers.SysLogHandler((syslog_host, syslog_port), syslog_facility)
            else:
                self.logger.debugMessage("Logging to file: %s" % log_file)
                try:
                    self.common_config["conf_log_handler"] = logging.FileHandler(log_file)
                except IOError, e:
                    self.logger.configError("cannot access to the log file: %s" % e)
                    sys.exit(1)
                    
        except ConfigParser.NoOptionError:    
            # no log defined in config file
            self.common_config["conf_log_handler"] = None
        
        try:
            self.common_config["daemon"] = self.config.get('main', 'daemon')
        except ConfigParser.NoOptionError:
            self.common_config["daemon"] = None
        try:
            self.common_config["pid_file"] = self.config.get('main', 'pid_file')
        except ConfigParser.NoOptionError:
            self.common_config["pid_file"] = None

        
        return self.common_config

    def parse_rules(self,prefix="rule_"):    
        self.regex = []
        self.subst = []
        self.label = []    
        self.match = []
        self.stop = []

        try:
            rules = sorted([i for i in self.config.sections() if i.startswith(prefix)], key=lambda num: int(num.split("_")[-1]))
        except ValueError, e:
            self.logger.configError("Invalid rule name: rule name mast be in format %sXX, where XX is a number, eg. %s13" % (prefix, prefix))
            self.logger.configError("Config details: %s" % e)
            sys.exit(1)

        if len(rules) <= 0:
            self.logger.infoMessage("No rule found with prefix '%s'" % prefix)
            return None

        self.logger.infoMessage("Valuating config sections order: %s" % rules)
    
        i = 0    
        for s in rules:
            if s.startswith(prefix):
                self.logger.debugMessage("Rule[%d]: %s" % (i,s))
                try:
                    match = self.config.get(s, "match")
                    if match not in ("uri", "headers", "new_header"):
                        self.logger.configError("Wrong match statement in %s section, match must be one of \"uri\", \"new_header\", \"del_header\" or \"headers\"" % s)
                        sys.exit(1)

                    # new_header and del_header doesn't require regex
                    elif match in ("new_header", "del_header"):
                        self.config.set(s, 'regex', '')

                except ConfigParser.NoOptionError:
                    self.logger.configError("Missing match statement in %s section, match must be \"uri\" or \"headers\"" % s)
                    sys.exit(1)
                try:
                    reg = self.config.get(s, 'regex')
                    sub = Template(self.config.get(s, 'subst')).safe_substitute(local_ip=self.common_config["local_ip"])
                except ConfigParser.NoOptionError:
                    self.logger.configError("Missing regex/subst option in %s section" % s)
                    sys.exit(1)
               
                try:
                    stop = self.config.get(s, "stop")
                    if stop.lower() not in ("yes", "no"):
                        self.logger.configError("Wrong stop statement in %s section, stop must be \"yes\" or \"no\"" % s)
                        sys.exit(1)
                except ConfigParser.NoOptionError:
                    stop = "no"

                self.logger.debugMessage("Regex: %s" % reg)
                self.logger.debugMessage("Subst: %s" % sub)
                self.logger.debugMessage("Match: %s" % match)
                self.logger.debugMessage("Stop: %s" % stop)

                try:
                    self.regex.append(re.compile(ur'%s' % reg, re.MULTILINE))
                except Exception, e:
                    raise InvalidRegexError("Regex: %s, Error: %s" % (reg, e))
    
                self.subst.append(ur'%s' % sub)
                self.label.append(s)
                self.match.append(match)
                self.stop.append(stop)
                i = i +1

        return {"regex": self.regex, "subst": self.subst, "label": self.label, "match": self.match, "stop": self.stop}

# daemonizing function
def become_daemon(pid_file=None):
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e:
        raise Exception("Fork failed, can't become daemon: %d (%s)" % (e.errno, e.strerror))
        sys.exit(1)
    os.chdir("/")
    os.setsid()
    os.umask(0)
    
    pid = os.getpid()
    if pid_file:
        try:
            f = open(pid_file, "w")
            f.write(str(pid)+"\n")
            f.close()
        except IOError:
            raise Exception('Cannot write PID in pidfile %s' % pid_file)
    return pid


#net functions
def get_ip_address():
    # This is a simple hack to find our IP address
    # AFAIK this is the only platform-independent way to obtain the address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('google.com', 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def is_valid_ipv4_address(address):
    try:
        addr = socket.inet_pton(socket.AF_INET, address)
    except AttributeError: # no inet_pton here, sorry
        try:
            addr= socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3 #invalidate shortened address (like 127.1)
    except socket.error: # not a valid address
        return False
    return True

def get_ip_address_ifname(iface):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', iface[:15])
    )[20:24])
