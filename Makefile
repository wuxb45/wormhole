# Makefile
# rules (always with .out)
# SRC-X.out += abc        # extra source: abc.c
# MOD-X.out += abc        # extra module: abc.c abc.h
# ASM-X.out += abc        # extra assembly: abc.S
# DEP-X.out += abc        # extra dependency: abc
# FLG-X.out += -finline   # extra flags
# LIB-X.out += abc        # extra -labc options

# X.out : xyz.h xyz.c # for extra dependences that are to be compiled/linked.

# X => X.out
TARGETS += easydemo concbench stresstest
# X => X.c only
SOURCES +=
# X => X.S only
ASSMBLY +=
# X => X.c X.h
MODULES += lib kv wh
# X => X.h
HEADERS += ctypes

FLG +=
LIB += m

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),FreeBSD)
LIB += execinfo
endif

# when $ make FORKER_PAPI=y
ifeq ($(strip $(FORKER_PAPI)),y)
LIB += papi
FLG += -DFORKER_PAPI
endif

bin : libwh.so
libwh.so : lib.c lib.h kv.c kv.h wh.c wh.h
	$(CCC) $(FLG) -shared -fPIC -o $@ lib.c kv.c wh.c

include Makefile.common
