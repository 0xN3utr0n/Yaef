#
# 0xN3utr0n - makefile sample
#

# MACROS

BPATH   = ./bin
CC      = cc
CFLAGS  =  -Wall -Wextra -Werror -pedantic -Wconversion -Wformat-security -std=gnu99 -march=x86-64
CFLAGS  += -fPIE -pie -fstack-clash-protection -fstack-protector --param ssp-buffer-size=4 
CFLAGS  += -Wl,-z,relro,-z,now
CFLAGS  += -Wl,-z,noexecstack -fomit-frame-pointer

#macro debug=1
ifeq ($(debug),1)
CFLAGS   += -g -DDEBUG
else
SECFLAGS += -O3 -D_FORTIFY_SOURCE=2
endif

# Targets

all: clean dummy yaef

clean:
	@rm -rf $(BPATH)/*

dummy: dummy.c
	@$(CC) $(CFLAGS) -o $(BPATH)/dummy dummy.c

yaef: Yaef.c Yaef.h
	@$(CC) $(CFLAGS) -o $(BPATH)/Yaef $^
	@echo OK
