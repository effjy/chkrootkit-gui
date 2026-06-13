# Makefile for chkrootkit-gui — a GTK3 front-end for chkrootkit
#
#   make            build the program
#   make run        build and run
#   sudo make install
#   sudo make uninstall

PROG    := chkrootkit-gui
SRC     := chkrootkit-gui.c
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
CFLAGS  += $(shell pkg-config --cflags gtk+-3.0)
LIBS    := $(shell pkg-config --libs gtk+-3.0)

PREFIX  ?= /usr/local
BINDIR  := $(DESTDIR)$(PREFIX)/bin
DATADIR := $(DESTDIR)$(PREFIX)/share
APPDIR  := $(DATADIR)/applications
ICONDIR := $(DATADIR)/icons/hicolor/scalable/apps

.PHONY: all run clean install uninstall

all: $(PROG)

$(PROG): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

run: $(PROG)
	./$(PROG)

clean:
	rm -f $(PROG)

install: $(PROG)
	install -d $(BINDIR)
	install -m 0755 $(PROG) $(BINDIR)/$(PROG)
	install -d $(ICONDIR)
	install -m 0644 $(PROG).svg $(ICONDIR)/$(PROG).svg
	install -d $(APPDIR)
	install -m 0644 $(PROG).desktop $(APPDIR)/$(PROG).desktop
	-gtk-update-icon-cache -f -t $(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(APPDIR) 2>/dev/null || true
	@echo "Installed $(PROG) to $(BINDIR)"

uninstall:
	rm -f $(BINDIR)/$(PROG)
	rm -f $(ICONDIR)/$(PROG).svg
	rm -f $(APPDIR)/$(PROG).desktop
	-gtk-update-icon-cache -f -t $(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(APPDIR) 2>/dev/null || true
	@echo "Uninstalled $(PROG)"
