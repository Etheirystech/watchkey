PREFIX ?= /usr/local

.PHONY: build install uninstall clean

build:
	swift build -c release

install: build
	install -d $(PREFIX)/bin
	install .build/release/watchkey $(PREFIX)/bin/watchkey

uninstall:
	rm -f $(PREFIX)/bin/watchkey

clean:
	swift package clean
