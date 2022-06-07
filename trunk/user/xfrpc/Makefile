THISDIR := $(shell pwd)
SRC_NAME := xfrpc
SRC_URL := https://github.com/liudf0716/xfrpc

all: download_test config_test
	$(MAKE) -j$(HOST_NCPU) -C $(SRC_NAME)/build

download_test:
	( if [ ! -d $(SRC_NAME) ]; then \
		git clone $(SRC_URL); \
	fi )

config_test:
	( if [ -f ./config_done ]; then \
		echo "the same configuration"; \
	else \
		make configure && touch config_done; \
	fi )

configure:
	( mkdir -p $(SRC_NAME)/build && cd $(SRC_NAME)/build ; \
	cmake -DCMAKE_TOOLCHAIN_FILE=../../cross-mipsel-linux.cmake .. \
	)

clean:
	rm -rf $(SRC_NAME)/build
	rm -f config_done xfrpc

romfs:
	$(ROMFSINST) -p +x $(THISDIR)/$(SRC_NAME)/build/xfrpc /usr/bin/frpc
	$(ROMFSINST) -p +x $(THISDIR)/frp.sh /usr/bin/frp.sh
	$(ROMFSINST) /etc_ro/frp_script.sh
