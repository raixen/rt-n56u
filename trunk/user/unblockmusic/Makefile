THISDIR = $(shell pwd)
export GO111MODULE=on
export GOPROXY=https://goproxy.io
UM_VERSION := 0.2.12
UM_URL := https://github.com/cnsilvan/UnblockNeteaseMusic/archive/$(UM_VERSION).tar.gz

all:build_extract build

build_extract:
	mkdir -p $(THISDIR)/bin
	mkdir -p $(THISDIR)/UnblockNeteaseMusicGo

build:
	( cd $(THISDIR)/UnblockNeteaseMusicGo; \
	tar -xzvf $(THISDIR)/UnblockNeteaseMusic-Go_$(UM_VERSION).tar.gz -C $(THISDIR)/UnblockNeteaseMusicGo; \
	\mv $(THISDIR)/UnblockNeteaseMusicGo/ca.crt $(THISDIR)/UnblockNeteaseMusicGo/server.* $(THISDIR)/file/ ; \
	)
	


clean:
	rm -rf $(THISDIR)/bin
	rm -rf $(THISDIR)/UnblockNeteaseMusicGo

romfs:
	$(ROMFSINST) $(THISDIR)/file/ /etc_ro/UnblockNeteaseMusicGo/
	mv $(THISDIR)/scripts/unblockmusic.sh $(THISDIR)/
	$(ROMFSINST) $(THISDIR)/scripts/ /usr/bin/
	$(ROMFSINST) +x $(THISDIR)/unblockmusic.sh /etc_ro/unblockmusic.sh
	ln -sf ../../etc/storage/unblockmusic.sh $(ROMFSDIR)/usr/bin/unblockmusic.sh
	$(ROMFSINST) -p +x $(THISDIR)/bin/UnblockNeteaseMusic /usr/bin/UnblockNeteaseMusic
