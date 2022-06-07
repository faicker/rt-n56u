url = https://fastly.jsdelivr.net/gh/misakaio/chnroutes2@master/chnroutes.txt
THISDIR = $(shell pwd)

all :
	( if [ ! -f chnroute.bz2 ];then \
		wget -t13 -4 --timeout=15 -O chnroute.txt '$(url)' && \
		tar jcf chnroute.bz2 chnroute.txt ;\
	fi )

romfs:
	chmod -R +x ./scripts
	$(ROMFSINST) $(THISDIR)/scripts/ /usr/bin/
	$(ROMFSINST) -d $(THISDIR)/chnroute.bz2 /etc_ro/chnroute.bz2

clean :
	rm -f chnroute.*
