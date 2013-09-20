# Modify CONFIG befor run the make command

include CONFIG
include VERSION

.PHONY: certs

BUILDDIR=build_tivano
BUILDTARDIR=$(NAME)_$(VERSION)

PYTHON_VERSION_FULL := $(wordlist 2,4,$(subst ., ,$(shell python -V 2>&1)))
PYTHON_VERSION_MAJOR := $(word 1,${PYTHON_VERSION_FULL})
PYTHON_VERSION_MINOR := $(word 2,${PYTHON_VERSION_FULL})
PYTHON_VERSION_PATCH := $(word 3,${PYTHON_VERSION_FULL})

# WGET command
WGET?=wget

# TODO: split substitutions between
# pre-dists substitution and installation substitution
# include AUTHOR, HOMEPAGE and so on in VERSION file 
do_subst = sed -e 's,__VERSION__,${VERSION},g' \
			-e 's,__PIDFILE__,$(PIDFILE),g' \
			-e 's,__LOGFILE__,$(LOGFILE),g' \
			-e 's,__DESTDIR__,$(DESTDIR),g' \
			-e 's,__DAEMONDIR__,$(DAEMONDIR),g' \
			-e 's,__CONFDIR__,$(CONFDIR),g' \
			-e 's,__PYTHON_LIB__,$(PYTHON_LIB),g' \
			-e 's,__ACCESS_LOG__,$(ACCESS_LOG),g' \
			-e 's,__CONFDIR__,$(CONFDIR),g' \

check-python-version:
	if [ ${PYTHON_VERSION_MAJOR} -eq 2 ]; then \
		if [ ${PYTHON_VERSION_MINOR} -gt 5 ]; then \
			echo "Detected Python:" ;\
			echo "Major: ${PYTHON_VERSION_MAJOR}" ;\
			echo "Minor: ${PYTHON_VERSION_MINOR}" ;\
		else \
			echo "Only Python > 2.5 is supported now"; \
			exit -1;\
		fi ;\
	else \
		echo "Only Python 2 is supported now..";\
		exit -1;\
	fi

build-setup:
	mkdir -p $(BUILDDIR)
	mkdir -p $(BUILDDIR)/$(DAEMONDIR)
	mkdir -p $(BUILDDIR)/$(INITDIR)
	mkdir -p $(BUILDDIR)/$(CONFDIR)
	mkdir -p $(BUILDDIR)/$(PYTHON_LIB)
	mkdir -p $(BUILDDIR)/tornado

tivano-bin:
	$(do_subst) < src/tivano.py > $(BUILDDIR)/$(DAEMONDIR)/tivano

tivano-init-script:
	$(do_subst) < src/tivano.init > $(BUILDDIR)/$(INITDIR)/tivano.init

tivano-conf:
	$(do_subst) < src/tivano.conf-default > $(BUILDDIR)/$(CONFDIR)/tivano.conf

build-clean: certs-clean
	rm -rf ${BUILDTARDIR}
	find src/ -name "*.pyc" | xargs rm -fr
	rm -rf $(BUILDDIR)
	rm -rf src/setup.py

certs-clean:
	cd certs; for a in *; do [ $$a == "makecerts.sh" -o $$a == "makeallcerts.sh" ] || rm -f $$a; done

tivanolib-build:
	$(do_subst) < src/setup.py.in > src/setup.py
	cd src && python setup.py build --build-lib ../$(BUILDDIR)/$(PYTHON_LIB)

tivanolib: tivanolib-build
	install -d -m 0755 $(PYTHON_LIB)
	install -d -m 0755 $(PYTHON_LIB)/tivano
	install -o $(USER) -g $(GROUP) -m 0644 $(BUILDDIR)/$(PYTHON_LIB)/tivano/__init__.py $(PYTHON_LIB)/tivano/__init__.py
	install -o $(USER) -g $(GROUP) -m 0644 $(BUILDDIR)/$(PYTHON_LIB)/tivano/daemon.py $(PYTHON_LIB)/tivano/daemon.py

certs:  build-setup
	#cd certs; ./makeselfcerts.sh ../$(BUILDDIR)/$(CONFDIR)/cert-key.pem
	#cd certs; cp verisign-ca.pem ../$(BUILDDIR)/$(CONFDIR)/ca.pem
	cd certs;\
	if ./makeallcerts.sh $(CONFDIR)/tivano.conf;\
	  then cp servercertkey.pem ../$(BUILDDIR)/$(CONFDIR)/cert-key.pem; cp cacert.pem ../$(BUILDDIR)/$(CONFDIR)/ca.pem;\
	else\
	  echo "configure me" > ../$(BUILDDIR)/$(CONFDIR)/cert-key.pem;\
	  echo "configure me" > ../$(BUILDDIR)/$(CONFDIR)/ca.pem;\
	fi

tivano: check-python-version build-clean build-setup tivano-bin tivano-init-script tivano-conf tivanolib tornado certs
	# install scripts
	install -d -m 0755 $(DAEMONDIR)
	install -d -m 0755 $(INITDIR)
	install -d -m 0750 $(CONFDIR)
	install -o $(USER) -g $(GROUP) -m 0755 $(BUILDDIR)/$(DAEMONDIR)/tivano $(DAEMONDIR)/tivano
	install -o $(USER) -g $(GROUP) -m 0755 $(BUILDDIR)/$(INITDIR)/tivano.init $(INITDIR)/tivano
	install -o $(USER) -g $(GROUP) -m 0644 $(BUILDDIR)/$(CONFDIR)/tivano.conf $(CONFDIR)/tivano.conf
	install -o $(USER) -g $(GROUP) -m 0600 $(BUILDDIR)/$(CONFDIR)/cert-key.pem $(CONFDIR)/cert-key.pem
	install -o $(USER) -g $(GROUP) -m 0600 $(BUILDDIR)/$(CONFDIR)/ca.pem $(CONFDIR)/ca.pem

tivano-remove:
	rm -f $(DAEMONDIR)/tivano
	rm -f $(CONFDIR)/tivano.conf
	rm -f $(INITDIR)/tivano
	rm -rf $(PYTHON_LIB)/tivano

tornado-build:
	cd $(BUILDDIR); $(WGET) $(TORNADO_TGZ); tar xzvf `basename $(TORNADO_TGZ)` -C tornado --strip-components 1
	cd $(BUILDDIR)/tornado && python setup.py build --build-lib ../$(PYTHON_LIB)

# install tornado python package
tornado: tornado-build
	#install -o $(USER) -g $(GROUP) -m 0644 $(BUILDDIR)/python-build/tornado $(PYTHON_LIB)/tornado
	cp -a $(BUILDDIR)/$(PYTHON_LIB)/tornado $(PYTHON_LIB)/

clean: build-clean

dist: build-clean
	mkdir ${BUILDTARDIR}
	# REMOVEME: !!!!
	cp -a src ${BUILDTARDIR}/
	cp -a certs ${BUILDTARDIR}/
	find ${BUILDTARDIR} -name .svn -type d | xargs rm -r
	find ${BUILDTARDIR} -name .git -type d | xargs rm -r
	cp changelog TODO CONFIG VERSION ${BUILDTARDIR}/
	cp Makefile ${BUILDTARDIR}/
	tar czvf ${BUILDTARDIR}.tgz ${BUILDTARDIR}
