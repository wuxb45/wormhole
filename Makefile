# Makefile
# no builtin rules/vars
MAKEFLAGS += -r -R

# targets
include Makefile.local

HDR = $(addsuffix .h,$(MODULES))
SRC = $(addsuffix .c,$(MODULES) $(SOURCES))
ASM = $(addsuffix .S,$(ASSMBLY))
DEP = Makefile Makefile.local $(HDR) $(SRC) $(ASM) $(EXTERNDEP) $(EXTERNSRC)
BIN = $(addsuffix .out,$(TARGETS))
DIS = $(addsuffix .dis,$(TARGETS))
CCC ?= clang

# clang:
# EXTRA="-Rpass=loop-vectorize"  # IDs loops that were successfully V-ed
# EXTRA="-Rpass-missed=loop-vectorize"  # IDs loops that failed V
# EXTRA="-Rpass-analysis=loop-vectorize" # IDs the statements that caused V to fail
# other passes: https://llvm.org/docs/Passes.html

# predefined OPT: make O={0g,3g,3p,2g,r,rg,c,mc,hc}
ifeq ($O,3g) # make O=3g
OPT ?= -g3 -O3 -flto -fno-inline
else ifeq ($O,3p) # make O=3p (profiling: no-inline)
OPT ?= -DNDEBUG -g3 -O3 -flto -fno-inline
else ifeq ($O,2g) # make O=2g
OPT ?= -g3 -O2 -flto -fno-inline
else ifeq ($O,r) # make O=r
OPT ?= -DNDEBUG -O3 -flto
else ifeq ($O,rg) # make O=rg
OPT ?= -g3 -DNDEBUG -O3 -flto
else ifeq ($O,san) # make O=san (address sanitizer)
OPT ?= -g3 -O0 -fsanitize=address -DHEAPCHECKING
else ifeq ($O,cov) # make O=c (for gcov)
OPT ?= -g3 -O0 --coverage
else ifeq ($O,mc) # make O=mc (for valgrind memcheck)
OPT ?= -g3 -O2 -fno-inline -DHEAPCHECKING
ARCH ?= broadwell
else ifeq ($O,hc) # make O=hc (for gperftools heapcheck)
OPT ?= -g3 -O2 -fno-inline
LIB += tcmalloc
else ifeq ($O,warn) # more warning
OPT ?= -g3 -O3 -Wvla -Wformat=2
else # 0g
OPT ?= -g3 -DNDEBUG -O3 -flto
endif

NBI += memcpy memmove memcmp
ARCH ?= native

# minimal arch requirement: -march=nehalem
FLG += -march=$(ARCH)
FLG += -pthread -std=gnu11 -Wall -Wextra -Wshadow
FLG += $(addprefix -fno-builtin-,$(NBI))
FLG += $(OPT)

.PHONY : bin dis clean cleanall check

bin : $(BIN)
dis : $(DIS) bin
.DEFAULT_GOAL = bin

.SECONDEXPANSION:
%.out : %.c $(DEP) $$(DEP-$$@) $$(addsuffix .c,$$(SRC-$$@) $$(MOD-$$@)) $$(addsuffix .h,$$(MOD-$$@)) $$(addsuffix .S,$$(ASM-$$@))
	$(eval ALLSRC := $(SRC) $(addsuffix .c,$(SRC-$@) $(MOD-$@)) $(ASM) $(addsuffix .S,$(ASM-$@)))
	$(eval ALLFLG := $(FLG) $(FLG-$@) -rdynamic)
	$(eval ALLLIB := $(addprefix -l,$(LIB) $(LIB-$@)))
	$(CCC) $(EXTRA) $(ALLFLG) -o $@ $< $(ALLSRC) $(ALLLIB)

%.dis : %.out
	objdump -SlwTC $< 1> $@ 2>/dev/null

%.o : %.c
	$(eval STEM := $(patsubst %.o,%,$@))
	$(CCC) $(EXTRA) $(FLG) $(FLG-$(STEM)) -o $@ -c $<

%.s : %.c
	$(eval STEM := $(patsubst %.o,%,$@))
	$(CCC) $(EXTRA) $(FLG) $(FLG-$(STEM)) -S -o $@ -c $<

clean :
	rm -rf *.out *.dis *.o *.gcda *.gcno *.gcov

cleanall :
	rm -rf *.out *.dis *.o $(EXTERNDEP) $(EXTERNSRC)

GCCINSTALL = "/usr/lib/gcc/$$(gcc -dumpmachine)/$$(gcc -dumpversion)"
check :
	cppcheck -I /usr/include -I /usr/local/include \
    -I $(GCCINSTALL)/include -I $(GCCINSTALL)/include-fixed \
    -q -D__x86_64__=1 -U__cplusplus --std=c11 --language=c --platform=unix64 --enable=all .
