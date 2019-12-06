# Makefile
# no builtin rules/vars (CC, CXX, etc. are still defined but will be empty)
MAKEFLAGS += -r -R

# targets
include Makefile.local

HDR = $(addsuffix .h,$(MODULES) $(HEADERS))
SRC = $(addsuffix .c,$(MODULES) $(SOURCES))
ASM = $(addsuffix .S,$(ASSMBLY))
DEP = Makefile Makefile.local $(HDR) $(EXTERNDEP) $(EXTERNSRC)
BIN = $(addsuffix .out,$(TARGETS))
DIS = $(addsuffix .dis,$(TARGETS))

# clang:
# EXTRA="-Rpass=loop-vectorize"  # IDs loops that were successfully V-ed
# EXTRA="-Rpass-missed=loop-vectorize"  # IDs loops that failed V
# EXTRA="-Rpass-analysis=loop-vectorize" # IDs the statements that caused V to fail
# EXTRA="-Rpass=\ *" # remarks for all passes
# other passes: https://llvm.org/docs/Passes.html

O ?= rg

# predefined OPT: make O={rg,r,0g,1g,2g,3g,3p,san,cov,mc,hc,warn,stk}
ifeq ($O,rg) # make O=rg
OPT ?= -DNDEBUG -g3 -O3 -flto -fno-stack-protector
else ifeq ($O,r) # make O=r
OPT ?= -DNDEBUG -O3 -flto -fno-stack-protector
else ifeq ($O,0g) # make O=0g
OPT ?= -g3 -O0 -fno-inline
else ifeq ($O,1g) # make O=1g
OPT ?= -g3 -O1 -fno-inline
else ifeq ($O,2g) # make O=2g
OPT ?= -g3 -O2 -flto -fno-inline
else ifeq ($O,3g) # make O=3g
OPT ?= -g3 -O3 -flto -fno-inline
else ifeq ($O,3p) # make O=3p (profiling: rg+noinline)
OPT ?= -DNDEBUG -g3 -O3 -flto -fno-inline -fno-stack-protector
else ifeq ($O,san) # make O=san (address sanitizer)
OPT ?= -g3 -O1 -fsanitize=address -fno-omit-frame-pointer -DHEAPCHECKING
else ifeq ($O,cov) # make O=c (for gcov)
OPT ?= -g3 -DNDEBUG -O0 --coverage
CCC = gcc
else ifeq ($O,mc) # make O=mc (for valgrind memcheck)
OPT ?= -g3 -O1 -fno-inline -DHEAPCHECKING
ARCH ?= broadwell
else ifeq ($O,hc) # make O=hc (for gperftools heapcheck)
OPT ?= -g3 -O1 -fno-inline
LIB += tcmalloc
else ifeq ($O,warn) # more warning
OPT ?= -g3 -O3 -Wvla -Wformat=2
else ifeq ($O,stk) # check stack usage with gcc
OPT ?= -g3 -O3 -DNDEBUG -fstack-usage
CCC = gcc
endif

# malloc: g:glibc, t:tcmalloc, j:jemalloc
M ?= g

ifeq ($M,t)
  LIB += tcmalloc
  FLG += -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free
else ifeq ($M,j)
  LIB += jemalloc
endif

CCC ?= clang
CSTD = -std=gnu11
XCC ?= clang++
XSTD = -std=gnu++17

ISA := $(shell uname -m)
ifeq ($(ISA),aarch64) # "native" does not work for clang@aarch64
ARCH ?= armv8-a+crc
else
ARCH ?= native
endif

TUNE ?= native

NBI += memcpy memmove memcmp

# minimal requirement on x86_64: -march=nehalem
# minimal requirement on aarch64: -march=armv8-a+crc
FLG += -march=$(ARCH) -mtune=$(TUNE)
FLG += -pthread -Wall -Wextra -Wshadow
FLG += $(addprefix -fno-builtin-,$(NBI))
FLG += $(OPT)

.PHONY : bin dis clean cleanall check tags

bin : $(BIN)
dis : $(DIS) bin
.DEFAULT_GOAL = bin

.SECONDEXPANSION:
%.out : %.c $(SRC) $(ASM) $(DEP) $$(DEP-$$@) $$(addsuffix .c,$$(SRC-$$@) $$(MOD-$$@)) $$(addsuffix .h,$$(HDR-$$@) $$(MOD-$$@)) $$(addsuffix .S,$$(ASM-$$@))
	$(eval ALLSRC := $(SRC) $(addsuffix .c,$(SRC-$@) $(MOD-$@)) $(ASM) $(addsuffix .S,$(ASM-$@)))
	$(eval ALLFLG := $(FLG) $(FLG-$@) -rdynamic)
	$(eval ALLLIB := $(addprefix -l,$(LIB) $(LIB-$@)))
	$(CCC) $(CSTD) $(EXTRA) $(ALLFLG) -o $@ $< $(ALLSRC) $(ALLLIB)

%.dis : %.out
	objdump -SlwTC $< 1> $@ 2>/dev/null

%.o : %.cc $(DEP) $$(DEP-$$@) $$(addsuffix .h,$$(HDR-$$@) $$(MOD-$$@))
	$(eval STEM := $(patsubst %.o,%,$@))
	$(XCC) $(XSTD) $(EXTRA) $(FLG) $(FLG-$(STEM)) -o $@ -c $<

%.o : %.c $(DEP) $$(DEP-$$@) $$(addsuffix .h,$$(HDR-$$@) $$(MOD-$$@))
	$(eval STEM := $(patsubst %.o,%,$@))
	$(CCC) $(CSTD) $(EXTRA) $(FLG) $(FLG-$(STEM)) -o $@ -c $<

%.s : %.c $(DEP) $$(DEP-$$@) $$(addsuffix .h,$$(HDR-$$@) $$(MOD-$$@))
	$(eval STEM := $(patsubst %.o,%,$@))
	$(CCC) $(CSTD) $(EXTRA) $(FLG) $(FLG-$(STEM)) -S -o $@ -c $<

clean :
	rm -rf *.out *.dis *.o *.gcda *.gcno *.gcov

cleanall :
	rm -rf *.out *.dis *.o $(EXTERNDEP) $(EXTERNSRC)

ifeq ($(CCC),gcc)
  CCINST = /usr/lib/gcc/$(shell gcc -dumpmachine)/$(shell gcc -dumpversion)
  CCINC = $(CCINST)/include $(CCINST)/include-fixed
else ifeq ($(CCC),clang)
  CCINST = /usr/lib/clang/$(shell clang --version | awk '/^clang/ { print $$3 }')
  CCINC = $(CCINST)/include
endif

check :
	cppcheck -I /usr/include -I /usr/local/include $(addprefix -I ,$(CCINC)) \
    -q -D__x86_64__=1 -U__cplusplus --std=c11 --language=c --platform=unix64 --enable=all .

tags :
	ctags -R . /usr/include /usr/local/include $(CCINC)
