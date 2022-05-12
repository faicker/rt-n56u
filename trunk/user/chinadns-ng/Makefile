url = https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/reject-list.txt
SRC_NAME = chinadns-ng
THISDIR = $(shell pwd)

all: 
	$(MAKE) -j$(HOST_NCPU) -C $(SRC_NAME)
	if [ ! -f adhosts.bz2 ];then \
		curl --retry 3 -4SkL '$(url)' | tr '\n' ' ' | sed -e 's/^/0.0.0.0 /' -e 's/ $$/\n/' > adhosts && \
		tar jcf adhosts.bz2 adhosts ;\
		fi


clean:
	if [ -f $(SRC_NAME)/Makefile ] ; then \
		$(MAKE) -C $(SRC_NAME) clean ; \
	fi ; \
	rm -f config_done ad_hosts*

romfs:
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/chinadns-ng /usr/bin/chinadns-ng
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/update-adhosts.sh /usr/bin/update_adhosts.sh
	$(ROMFSINST) -d $(THISDIR)/adhosts.bz2 /etc_ro/adhosts.bz2

