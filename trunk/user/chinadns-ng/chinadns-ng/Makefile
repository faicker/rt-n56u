CC ?= gcc
DEBUG ?= 0
ifeq ($(DEBUG), 1)
	DEBUGFLAG=-O0 -g
else
	DEBUGFLAG=-O2
endif
CFLAGS = -std=c99 -Wall -Wextra $(DEBUGFLAG)
SRCS = chinadns.c dnsutils.c dnlutils.c netutils.c
OBJS = $(SRCS:.c=.o)
DATAS = utils/chnroute.ipset utils/chnroute6.ipset utils/chnlist.txt utils/gfwlist.txt utils/hosts
MAIN = chinadns-ng
DESTDIR = /usr/bin
DATADIR = /usr/share/$(MAIN)

.PHONY: all install uninstall clean

all: $(MAIN)

install: $(MAIN)
	install -d $(DESTDIR)
	install -m 0755 $(MAIN) $(DESTDIR)
	mkdir -p $(DATADIR)
	install -m 0755 $(DATAS) $(DATADIR)

uninstall:
	$(RM) $(DESTDIR)/$(MAIN)
	$(RM) -rf $DATADIR

clean:
	$(RM) *.o $(MAIN)

$(MAIN): $(OBJS)
	$(CC) $(CFLAGS) -o $(MAIN) $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
