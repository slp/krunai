OS = $(shell uname -s)
KRUNAI_RELEASE = target/release/krunai
KRUNAI_DEBUG = target/debug/krunai

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

.PHONY: install clean

all: $(KRUNAI_RELEASE)

debug: $(KRUNAI_DEBUG)

$(KRUNAI_RELEASE):
	cargo build --release
ifeq ($(OS),Darwin)
	codesign --entitlements krunai.entitlements --force -s - $@
endif

$(KRUNAI_DEBUG):
	cargo build --debug

install: $(KRUNAI_RELEASE)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(KRUNAI_RELEASE) $(DESTDIR)$(PREFIX)/bin

clean:
	cargo clean
