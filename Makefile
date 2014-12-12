#!/usr/bin/make -f

#   This file is part of iouyap, a program to bridge IOU with
#   network interfaces.
#
#   Copyright (C) 2013, 2014  James E. Carpenter
#
#   iouyap is free software: you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   iouyap is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

SHELL = /bin/sh
BINDIR = /usr/local/bin

srcdir = .

CC = gcc -I #-O3
CDEBUG = -g -DDEBUG
CFLAGS = $(CDEBUG) -Wall

LDLIBS = -liniparser -lpthread
LDFLAGS =

YACC = bison -y
YFLAGS = -d

LEX = flex
LFLAGS =

objects = netmap_parse.o netmap_scan.o netmap.o config.o iouyap.o

all : iouyap

iouyap : $(objects)

$(objects) : iouyap.h netmap.h config.h

.PHONY : clean
clean :
	-rm iouyap y.tab.* *.o

install : iouyap
	chmod +x iouyap
	sudo cp iouyap $(BINDIR)
        sudo setcap cap_net_admin,cap_net_raw=ep iouyap

