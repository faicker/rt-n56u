SRC_NAME = gsocket
THISDIR = $(shell pwd)

all: extract_test config_test
	$(MAKE) -j$(HOST_NCPU) -C $(SRC_NAME)

extract_test:
	( if [ ! -d $(SRC_NAME) ]; then \
		tar zxf $(SRC_NAME).tar.gz; \
	fi )
	
config_test:
	( if [ -f ./config_done ]; then \
		echo "the same configuration"; \
	else \
		make configure && touch config_done; \
	fi )

configure:
	( cd $(SRC_NAME) ; \
	./bootstrap ; \
	./configure \
		PKG_CONFIG_LIBDIR="$(STAGEDIR)/lib/pkgconfig" \
		LDFLAGS="-L$(STAGEDIR)/lib" \
		CFLAGS="-I$(STAGEDIR)/include" \
		--host=$(HOST_TARGET) \
		--build=$(HOST_BUILD) ; \
	)

clean:
	if [ -f $(SRC_NAME)/Makefile ] ; then \
		$(MAKE) -C $(SRC_NAME) distclean ; \
	fi ; \
	rm -f config_done

romfs:
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/tools/gsocket /usr/bin/gsocket
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/tools/gs-netcat /usr/bin/gs-netcat
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/tools/gs-sftp /usr/bin/gs-sftp
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/tools/gs_funcs /usr/bin/gs_funcs
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/tools/gs-mount /usr/bin/gs-mount
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/tools/blitz /usr/bin/blitz
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/tools/gsocket_dso.so.0 /lib
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/tools/gsocket_uchroot_dso.so.0 /lib
