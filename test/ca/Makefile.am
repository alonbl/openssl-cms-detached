MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

clean-local:
	rm -fr rootca.pki built.rootca
	rm -fr subca.pki built.subca

check-local: 	\
		built.rootca	\
		built.subca \
		$(NULL)

dist_noinst_SCRIPTS = \
	issue.sh \
	$(NULL)

dist_noinst_DATA = \
	oids.cnf \
	x509-types/COMMON \
	x509-types/ca \
	x509-types/encrypt \
	x509-types/sign \
	$(NULL)

built.rootca:	\
		oids.cnf \
		$(NULL)
	rm -f built.rootca init-pki
	$(EASYRSA) --vars="./rootca.vars" init-pki
	touch rootca.pki/.rnd
	$(EASYRSA) --vars="./rootca.vars" build-ca nopass
	touch built.rootca

built.subca:	\
		built.rootca \
		oids.cnf \
		$(NULL)
	rm -f built.subca subca.pki
	$(EASYRSA) --vars="./subca.vars" init-pki
	touch subca.pki/.rnd

	cat "$(srcdir)/oids.cnf" >> subca.pki/openssl-easyrsa.cnf
	sed -i '1i oid_section = oids' subca.pki/openssl-easyrsa.cnf

	$(EASYRSA) --vars="./subca.vars" build-ca nopass subca
	$(EASYRSA) --vars="./rootca.vars" import-req ./subca.pki/reqs/ca.req subca
	$(EASYRSA) --vars="./rootca.vars" sign-req ca subca
	cp ./rootca.pki/issued/subca.crt ./subca.pki/ca.crt
	touch built.subca
