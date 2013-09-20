#!/usr/bin/env python
# vi:si:et:sw=4:sts=4:ts=4
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-

import sys
import socket
import os
import ssl
import signal
import ConfigParser
import logging
import re
import contextlib

import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.httpclient
import tornado.log

from string import Template

from tivano import daemon

version = "__VERSION__"

proxy_logger = daemon.Logger("proxy")
# Disable log propagatin
proxy_logger.logger.propagate = False

class SocketOptionError(Exception): pass
class CreateSocketError(Exception): pass
class BindSocketError(Exception): pass
class InvalidRegexError(Exception): pass
class SendDataError(Exception): pass

class CustomTemplate(Template):
    idpattern = r'[a-z][\.\-_a-z0-9]*'

class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST']

    def initialize(self, request_rules, forward_headers, send_headers):
        self.regex = request_rules["regex"]
        self.subst = request_rules["subst"]
        self.label = request_rules["label"]
        self.match = request_rules["match"]
        self.stop = request_rules["stop"]
        self.forward_headers = forward_headers
        self.send_headers = send_headers
        self.url = None

    def check_request(self):
        """
        set self.url
        """
        # Evaluating request
        i = 0
        while i < len(self.subst):
            r = self.regex[i]
            proxy_logger.debugMessage("Evaluating rule num %d (%s)" % (i, self.label[i]))
            proxy_logger.debugMessage("Pattern: %s" % r.pattern)
            proxy_logger.debugMessage("Subst: %s" % self.subst[i])
            proxy_logger.debugMessage("Match: %s" % self.match[i])
            proxy_logger.debugMessage("Stop: %s" % self.stop[i])

            new_reg = CustomTemplate(r.pattern).safe_substitute(self.template_vars)
            replacement = CustomTemplate(self.subst[i]).safe_substitute(self.template_vars)
            
            if self.match[i] == "uri":
                proxy_logger.debugMessage("Appling URI substitution: pattern: %s, replacement: %s, URI: %s" % (new_reg, replacement, self.request.uri))
                res = re.sub(new_reg, replacement, self.request.uri)
                # URI matched:
                #if res != self.request.uri:
                #proxy_logger.infoMessage("HTTP request found: rule number: %d" % i)
                proxy_logger.debugMessage("URI substitution result: %s" % res)
                if res.split(":")[0] == "GOTO":
                    goto_label = res.split(":")[1]
                    proxy_logger.debugMessage("Found GOTO statement: GOTO label -> '%s'" % goto_label)
                    goto_index = self.label.index(goto_label)
                    proxy_logger.debugMessage("Found GOTO statement: GOTO index -> '%d'" % goto_index)
                    self.request.uri = ":".join(res.split(":")[2:])
                    proxy_logger.debugMessage("Found GOTO statement: Rewritten URI: %s" % self.request.uri)
                    i = goto_index
                    continue

                self.request.uri = res

            elif self.match[i] == "headers":
                for header in self.request.headers:
                    full_header = "%s: %s" % (header, self.request.headers[header])
                    proxy_logger.debugMessage("Appling header substitutin: pattern: %s, replacement: %s, header: %s" % (new_reg, replacement, full_header))
                    res = re.sub(new_reg, replacement, full_header)
                    self.request.headers[header] = "".join(res.split(": ")[1:])
                    proxy_logger.debugMessage("Header substitution result: %s: %s" % (header, self.request.headers[header]))
            
            elif self.match[i] == "new_header":
                proxy_logger.debugMessage("Adding the new header %s" % replacement)
                header_name = replacement.split(": ")[0]
                header_value = ":".join(replacement.split(":")[1:])
                self.request.headers.update({header_name: header_value})
            if self.stop[i] == "yes":
                proxy_logger.debugMessage("Found 'stop' statement in rule, exit from rule evaulation")
                return

            i = i + 1

        return

    def parse_ssl_cert(self,cert=None):
        if cert == None:
            return None
        ret = {}
        ret['client_cert_notAfter'] = cert['notAfter']
        for rdn in cert['subject']:
            field_name = "client_cert_%s" % rdn[0][0]
            ret[field_name] = rdn[0][1]
        return ret

    @tornado.web.asynchronous
    def get(self):

        # create the template_vars property
        self.template_vars = {"original_uri": self.request.uri,
                      "remote_ip": self.request.remote_ip,}
        headers = {}
        for k in self.request.headers:
            headers["client_header_%s" % k] = self.request.headers[k]

        self.template_vars.update(headers)

        def handle_response(response):
            if response.error and not isinstance(response.error,
                    tornado.httpclient.HTTPError):
                proxy_logger.errorMessage("Error during fetching remote URL: %s" % response.error)
                self.set_status(500)
                self.write('Internal server error:\n')
                self.finish()
            else:
                self.set_status(response.code)
                #if "*" in self.forward_headers:
                for header in response.headers:
                    if header in self.forward_headers or "*" in self.forward_headers:
                #for header in self.forward_headers:
                        v = response.headers.get(header)
                        if v:
                            proxy_logger.debugMessage("Forwarding HTTP header %s: %s" % (header, v))
                            self.set_header(header, v)
                if response.body:
                    self.write(response.body)
                self.finish()

        proxy_logger.debugMessage("HTTP request received: URI:\t%s" % self.request.uri)
        proxy_logger.debugMessage("HTTP request received: Method:\t%s" % self.request.method)
        proxy_logger.debugMessage("HTTP request received: Headers:\t%s" % self.request.headers)
        proxy_logger.debugMessage("HTTP request received: Body:\t%s" % self.request.body)

        self.client_cert = self.parse_ssl_cert(self.request.get_ssl_certificate())

        if self.client_cert:
            proxy_logger.debugMessage("Client certificate: %s" % self.client_cert)
        else:
            self.client_cert = {}
            proxy_logger.debugMessage("No client certificate provided")

        self.template_vars.update(self.client_cert)
        orig_uri = self.request.uri
        self.check_request()

        # No rule found:
        if self.request.uri == orig_uri:
            proxy_logger.debugMessage("No rule found, sending error 500")
            self.set_status(500)
            self.write('No roule found')
            self.finish()
            return

        # the rule starts with DENY:501 Internal server error
        if self.request.uri.startswith("DENY:"):
            proxy_logger.debugMessage("Found a DENY message")
            proxy_logger.debugMessage("Setting status code: %d" % int(self.request.uri.split(":")[1:][0]))
            self.set_status(int(self.request.uri.split(":")[1:][0]))
            self.write(" ".join(self.request.uri.split(":")[1:]))
            self.finish()
            return

        # send out the HTTP request
        proxy_logger.debugMessage("Sending HTTP request to: %s " % self.request.uri)

        # compile custom headers
        for name in self.send_headers:
            new_value = CustomTemplate(self.send_headers[name]).safe_substitute(self.template_vars)
            proxy_logger.debugMessage("Compiling custom header '%s:%s'" % (name, new_value))
            self.request.headers.update({name: new_value})

        req = tornado.httpclient.HTTPRequest(url=self.request.uri, method=self.request.method, body=self.request.body,
                headers=self.request.headers, follow_redirects=False,
                allow_nonstandard_methods=True)

        client = tornado.httpclient.AsyncHTTPClient()

        try:
            client.fetch(req, handle_response)
        except tornado.httpclient.HTTPError, e:
            if hasattr(e, 'response') and e.response:
                handle_response(e.response)
            else:
                proxy_logger.errorMessage("Error in sending request to '%s': %s" % (self.request.uri, str(e)) )
                self.set_status(500)
                self.write('Internal server error\n')
                self.finish()

    @tornado.web.asynchronous
    def post(self):
        return self.get()

def run_proxy(port, local_ip, certs, logger, request_rules, forward_headers, send_headers):

    def proxy_log(handler):
        if handler.get_status() < 400:
            log_method = logger.info
        elif handler.get_status() < 500:
            log_method = logger.warning
        else:
            log_method = logger.error
        request_time = 1000.0 * handler.request.request_time()
        log_method ("%d %s %.2fms" % (handler.get_status(), handler._request_summary(), request_time))

    app = tornado.web.Application([
            (r'.*', ProxyHandler, dict(request_rules = request_rules,
                                    forward_headers = forward_headers,
                                    send_headers = send_headers)),
        ],log_function=proxy_log)

    http_server = tornado.httpserver.HTTPServer(app,ssl_options={
        "certfile":  certs['server_cert'],
        "keyfile": certs['server_key'],
        "ca_certs": certs['clients_cert'],
        "cert_reqs": certs['enforce_clients_cert'],
        "ssl_version": ssl.PROTOCOL_SSLv23,
        })

    try:
        http_server.listen(port, address=local_ip)
        ioloop = tornado.ioloop.IOLoop.instance()
        try:
            ioloop.start()
        except Exception, e:
            proxy_logger.systemError("Exception on IOLoop: %s" % e)
            sys.exit(-1)
    except Exception, e:
        proxy_logger.systemError("Cannot start HTTPS proxy: %s" % e)
        sys.exit(-1)

if __name__ == '__main__':

    def usage():
        print "\nUsage: %s [options] <config-file>" % sys.argv[0]
        print "\n\tOptions:"
        print "\t\t-s <config-file>\t\tStart the program"
        sys.exit()

    def signal_handler(signal, frame):
        proxy_logger.infoMessage('Killed by SIGTERM. Goodbye.')
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)

    # TODO: improve command line handling
    # an move it in tivano package
    if len(sys.argv) < 3:
        print "\nERROR: missing args."
        usage()

    if sys.argv[1] not in ["-s"]:
        print "\nERROR: wrong arg."
        usage()

    parser = daemon.SettingsParser(sys.argv[2], proxy_logger)
    config = parser.get_config()
    main_settings = parser.parse_main()

    if main_settings["debug"].upper() == 'TRUE':
        proxy_logger.set_level("debug")
        proxy_logger.debugMessage("Log level: DEBUG")
    else:
        proxy_logger.set_level("info")
        proxy_logger.debugMessage("Log level: INFO")

    local_ip = main_settings["local_ip"]

    if main_settings["conf_log_handler"]:
        proxy_logger.debugMessage("Logging to %s" % main_settings["log_file"])
        proxy_logger.change_handler(main_settings["conf_log_handler"])

    # non-common setting
    try:
        port = int(config.get('main', 'listen_port'))
        proxy_logger.debugMessage("Using %d as TCP listen port" % int(port))
    except ConfigParser.NoOptionError:
        port = 443

    try:
        server_cert = config.get('main', 'server_cert')
        if not os.access(server_cert, os.R_OK):
            proxy_logger.systemError("Cannot open server certificate %s, bye." % server_cert)
            sys.exit(-1)
        proxy_logger.debugMessage("Using %s as server certificate" % server_cert)

    except ConfigParser.NoOptionError:
        proxy_logger.systemError("No server_cert defined, bye.")
        sys.exit(-1)

    try:
        server_key = config.get('main', 'server_key')
        if not os.access(server_key, os.R_OK):
            proxy_logger.systemError("Cannot open server private key %s, bye." % server_key)
            sys.exit(-1)
        proxy_logger.debugMessage("Using %s as server private key" % server_key)

    except ConfigParser.NoOptionError:
        proxy_logger.systemError("No server_key defined, bye.")
        sys.exit(-1)

    try:
        clients_cert = config.get('main', 'clients_cert')
        if not os.access(clients_cert, os.R_OK):
            proxy_logger.systemError("Cannot open cliens CA certificate %s, bye." % clients_cert)
            sys.exit(-1)
        proxy_logger.debugMessage("Using %s as clients CA certificate" % clients_cert)

    except ConfigParser.NoOptionError:
        proxy_logger.systemError("No clients_cert defined, bye.")
        sys.exit(-1)

    try:
        c_enforce_clients_cert = config.get('main', 'enforce_clients_cert')
        if c_enforce_clients_cert.upper() == "NO":
            enforce_clients_cert = ssl.CERT_NONE
        elif c_enforce_clients_cert.upper() == "YES":
            enforce_clients_cert = ssl.CERT_REQUIRED
        elif c_enforce_clients_cert.upper() == "OPTIONAL":
            enforce_clients_cert = ssl.CERT_OPTIONAL
        else:
            proxy_logger.systemError("No valid value for 'enforce_clients_cert' (must be one of yes, no, optional)")
            sys.exit(-1)
        proxy_logger.debugMessage("Using 'enforce_clients_cert' = %s" % c_enforce_clients_cert.upper())

    except ConfigParser.NoOptionError:
        proxy_logger.debugMessage("No 'enforce_clients_cert' defined, assuming YES")
        enforce_client_cert = ssl.CERT_REQUIRED

    try:
        forward_headers = config.get('main', 'forward_headers').split(",")
        proxy_logger.debugMessage("Using 'forward_headers: '%s'" % ','.join(forward_headers))
    except ConfigParser.NoOptionError:
        forward_headers = ['Date', 'Cache-Control', 'Server',
                        'Content-Type', 'Location', 'Content-Length']
        proxy_logger.debugMessage("No 'forward_headers' using default: '%s'" % ','.join(forward_headers))

    # send_header parsing
    try:
        pref = 'send_header_'
        send_headers = dict([(n[len(pref):],v) for (n,v) in config.items('main') if n.startswith(pref)])
        proxy_logger.debugMessage("Sending HTTP Headers: %s" % send_headers)
    except Exception, e:
        proxy_logger.errorMessage("Error in parsinf 'send_header_' statement: %s" %e)

    try:
        forward_headers = config.get('main', 'forward_headers').split(",")
        proxy_logger.debugMessage("Using 'forward_headers: '%s'" % ','.join(forward_headers))
    except ConfigParser.NoOptionError:
        forward_headers = ['Date', 'Cache-Control', 'Server',
                        'Content-Type', 'Location', 'Content-Length']
        proxy_logger.debugMessage("No 'forward_headers' using default: '%s'" % ','.join(forward_headers))

    try:
        access_log = config.get('main', 'access_log')
    except ConfigParser.NoOptionError:
        proxy_logger.systemError("No webserver access_log defined")
        sys.exit(-1)

    # TODO: use the same mechanism of daemon logging.
    tornado_logger_access = logging.getLogger("tornado.access")
    tornado_hdlr = logging.FileHandler(access_log)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    tornado_hdlr.setFormatter(formatter)
    tornado_logger_access.addHandler(tornado_hdlr)
    tornado_logger_access.setLevel(logging.WARNING)
    tornado_logger_access.propagate = False

    certs = {
        'server_cert': server_cert,
        'server_key': server_key,
        'clients_cert': clients_cert,
        'enforce_clients_cert': enforce_clients_cert
    }

    request_rules = parser.parse_rules(prefix="rule_")

    try:
        if config.get('main', 'daemon').upper() == 'TRUE':
            proxy_logger.infoMessage('Daemonizing')
            try:
                pid_file = config.get('main', 'pid_file')
                proxy_logger.infoMessage('Using pid file %s' % pid_file)
                try:
                    pid = daemon.become_daemon(pid_file)
                except Exception, e:
                    proxy_logger.systemError("Cannot start daemon: %s, exiting" %  e)
                    sys.exit(-1)
            except ConfigParser.NoOptionError:
                try:
                    pid = daemon.become_daemon(None)
                except Exception, e:
                    proxy_logger.systemError("Cannot start daemon: %s, exiting" % e)
                    sys.exit(-1)
                proxy_logger.infoMessage('No pid file in configuration file')
            proxy_logger.infoMessage("Daemon started with pid %d" % pid)

        proxy_logger.infoMessage("Starting HTTP proxy on %s:%d" % (local_ip, port))
    except ConfigParser.NoOptionError:
        proxy_logger.infoMessage('Run in foreground')
    try:
        run_proxy(    port = port,
                local_ip = local_ip,
                certs = certs, logger = tornado_logger_access,
                request_rules = request_rules,
                forward_headers = forward_headers,
                send_headers = send_headers)
    except Exception, e:
        proxy_logger.systemError('Received exception: %s' % e)
