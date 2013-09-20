# tivano

## Status of the project

You can consider tivano as a 'working beta' 

## Intro

tivano is an HTTPS reverse proxy based on a regex powered engine.

### What can I do using tivano ?

- you can configure tivano as a frontend server exposing HTTPS services
- you can perform TLS client authentication using certificates
- you can rewrite client requested URI using a powerful regular expression mechanism
- you can modify HTTP headers sent by client

### How tivano is implemented ? 

Tivano is a pure python HTTPS proxy running over the asynchronous [Tornado](http://www.tornadoweb.org).

## Tivano fast start

### Installation

The installation process is a simple task based on a Makefile, before starting the installation process you must edit the **CONFIG** file placed in the main directory.
The **CONFIG** file declares some variables defining the destination directories:

- **DESTDIR**: this one defines the main destination directory: here all tivano files will be places
- **PYTHON_LIB**: the installation process installs a few of needed python modules, these modules will be installed here
- **INITDIR**: here the init script will be placed, if you want to integrate tivano into your startup system can be useful to declare here the */etc/init.d/* path.
- **DAEMONDIR**: the main script will be placed here
- **CONFDIR**: the configuration file will be placed here
- **USER** and **GROUP**: the user/group ownership
- **PIDFILE**: the pidfile
- **LOGFILE**: the daemon log file
- **ACCESS_LOG**: the HTTP access log
- **WGET**: this variable defines the binary used to download some needed packages (Eg. Tornado web server)

### Running the installation

When the **CONFIG** file is well configured you can run the command

    make tivano
    
During the installation process you can decide to create needed self-signed certificates, is recomended to use self-generated certificates only for testing purpose, in a production enviroment use your own Certification Authority to generate server and client certificates.

If the installation process ends without error you're ready to configure the daemon.

### Configuration

Tivano is managed trough a simple configuration file.

The config file consists of two kind of sections:

- **main**: this section is declared by the *[main]* statement, here system paramethers such TCP port, log file, verbosity and so on are defined
- **rules**: this section is declared by the *[rule_XX]* statement, every rule defines a rule which permit to manipulate URI, Headers, etc… Every rule name must me in format **rule_XX** where **XX** is a number representing the rule order. Rules are evalued following the order.

#### The [main] section

In this section you can declare some paramethers:

- **local_ip**: the binding IP address where the daemon must be in listening over the TCP port, here you can insert
  - an ip address like *172.16.18.99*
  - the interface name, like *eth0*
  - *default*. Using *default* the daemon will try to discover the default ip address used to reach *google.com*
- **listen_port**: the TCP listening port
- **pid_file**: the PID file were the daemon write the background process PID number
- **log_file**: the log file, here you can declare a file path (Eg. */var/log/tivano.log*) or a syslog server using the following syntax: *syslog:host:port:facility* (Eg.: *syslog:172.16.18.200:514:local7*) for a complete list of syslog facility read the default config file of the syslog documentation. If you leave this paramether unconfigured log messages will be sent on the standard output
- **debug**: can be *True* of *False*, using *True* enables more verbosity, don't use debug mode in production
- **enforce_clients_cert**: this one can be *yes*, *not* or *optional*. A value of *yes* performs client SSL certificates validation against the **CA** certificate defined by **clients_cert**, a value of *not* doesn't asks for client certificates, *optional* perform the validation only if the client certificate is provided
- **access_log**: defines the access log file path
- **daemon**: can be *True* or *False*, using *False* the daemon stills in foreground, useful for debug purpose
- **server_cert**: the HTTPS server certificate
- **server_key**: the HTTPS server key
- **clients_cert**: the CA used in client certificates validation
- **forward_headers**: here you can declare a comma separated list of HTTP headers forwrded from the remote server to the client during the HTTP response
- **send_header_Header_name**: you can define many HTTP headers to send to the *send_header_Header_name* (Eg. *send_header_X-Custom-header = Tivano forwarded* will send an HTTP header with name **X-Custom-Header: Tivano forwarded**) here you can use some Runtime Variables

#### Rules

Using rules you can configure the tivano rulset.

Every rule is declared using a section name staring with **rule_** followed by the rule number (Eg.: *rule_120*). Rules are evaulated sequentially starting from the lowest rule number, when a rule with *stop = yes* is found the evaluation process is interrupted and the HTTP request will be composed.

Every rule must declare these statements:

- **match**: defines the kind of rule can be one of the following:
  - *uri*: the rule will be evaulated against the request URI, the substitution will be applied to the URI
  - *headers*: the rule will be evaulated agains the client headers, the substitution will be applied to the matching header
  - *new_header*: a new header will be added to the request
- **regex**: a regular expression evaluated against the URI in case of *match = uri* or against HTTP headers in case of *match = headers*, not used in case on *match = new_header*. In *regex* statement you can define some [matching group](http://docs.python.org/2/howto/regex.html#grouping). Here you can use runtime variables
- **subst**: the substitution applied to the regular expression, here you can refer to matching groups defined in *regex*, and use runtime variables too. In *subst* statement you can perform jumps between rules using the syntax *GOTO:RULE_XXX:new_uri*, Eg.: *GOTO:rule_110:http://www.bertera.it/tivano/test-tivano.php?ORIG_URIA=\1* Will jump to the rule *rule_110* with a new URI. 

#### Example

**TODO**

#### Testing

**TODO**


#### Runtime variables

In **subst**, **regex** rules statements and in **send_header_*** statement you can use some variables that will be replaced at runtime:

- **${local_ip}**: contains the *local_ip* value
- **${client_cert_notAfter}**: contains the client certificate expiry timestamp (present only if a certificate is provided)
- **${client_cert_XXXXX}**: you can use the RDN fields extraced from the client certificate Subject, Eg.: *${client_cert_commonName}* will contains the commonName, *${client_cert_commonorganizationName}* will contains the organizationName
- **${client_header_XXXX}**: HTTP headers sent by the client, Eg.: *${client_header_User-Agent}* contains the received HTTP *User-Agent* header
- **{original_uri}**: the original request URI
