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
TARGETS += demo1 concbench stresstest
# X => X.c only
SOURCES +=
# X => X.S only
ASSMBLY +=
# X => X.c X.h
MODULES += lib wh
# X => X.h
HEADERS += ctypes

FLG +=
LIB += rt m

# when $ make FORKER_PAPI=y
ifeq ($(strip $(FORKER_PAPI)),y)
LIB += papi
FLG += -DFORKER_PAPI
endif

bin : libwh.so
libwh.so : wh.c wh.h lib.c lib.h
	$(CCC) $(FLG) -shared -fPIC -o $@ wh.c lib.c

include Makefile.common
