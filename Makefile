# rak-fuzzy - fuzzy hashing library for the Rak language.
#
# The same Makefile builds on Linux and on Windows with MSYS2 / MinGW-w64.
#   make            build the shared library and the tests
#   make lib        build the shared library only
#   make test       build and run the test suite
#   make bench      build and run the tests including the throughput benchmark
#   make sanitizer  build and run the tests with address and UB sanitizers
#   make clean      remove all build artefacts
#
# On Linux the library is called librak_fuzzy.so, on Windows rak_fuzzy.dll.

CXX      ?= g++
OPT      ?= -O2
CXXSTD   ?= -std=c++17
WARN     ?= -Wall -Wextra
CXXFLAGS ?= $(OPT) $(CXXSTD) $(WARN)

UNAME_S := $(shell uname -s 2>/dev/null || echo unknown)

# Directory creation and removal that work both in a POSIX shell (MSYS2,
# Linux) and in a plain Windows command prompt (mingw32-make).
ifeq ($(OS),Windows_NT)
  MKDIR := cmd /C mkdir
  RM    := cmd /C rmdir /S /Q
else
  MKDIR := mkdir -p
  RM    := rm -rf
endif

ifeq ($(UNAME_S),Linux)
  LIBNAME  := librak_fuzzy.so
  SHARED   := -shared -fPIC
  PICFLAGS := -fPIC
  EXEEXT   :=
  TESTLIBS :=
  LDFLAGS  ?= -static-libgcc -static-libstdc++
else
  LIBNAME  := rak_fuzzy.dll
  SHARED   := -shared
  PICFLAGS :=
  EXEEXT   := .exe
  # GetProcessMemoryInfo() lives in psapi on Windows.
  TESTLIBS := -lpsapi
  # -static keeps libwinpthread-1.dll out of the import table, so the DLL
  # can be loaded by any host application without extra runtime libraries.
  LDFLAGS  ?= -static -static-libgcc -static-libstdc++
endif

SRCDIR   := src
TESTDIR  := tests
BUILDDIR ?= build

# The TLSH-like digest is optional. Build without it with "make TLSH=0";
# the rf_tlsh_* entry points then report RF_ERR_UNSUPPORTED.
TLSH ?= 1

SRCS := $(SRCDIR)/ctph.cpp $(SRCDIR)/cluster.cpp $(SRCDIR)/api.cpp
DEFS := -DRAK_FUZZY_BUILDING
ifeq ($(TLSH),1)
  SRCS := $(SRCDIR)/tlsh_like.cpp $(SRCS)
  DEFS += -DRAK_FUZZY_ENABLE_TLSH
endif

OBJS := $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SRCS))

TEST_BINS := $(BUILDDIR)/test_ctph$(EXEEXT) $(BUILDDIR)/test_cluster$(EXEEXT)

.PHONY: all lib tests test bench sanitizer clean

all: lib tests

lib: $(BUILDDIR)/$(LIBNAME)

tests: $(TEST_BINS)

$(BUILDDIR):
	$(MKDIR) $(BUILDDIR)

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(PICFLAGS) $(DEFS) -c -o $@ $<

$(BUILDDIR)/test_ctph.o: $(TESTDIR)/test_ctph.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(DEFS) -c -o $@ $<

$(BUILDDIR)/test_cluster.o: $(TESTDIR)/test_cluster.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(DEFS) -c -o $@ $<

$(BUILDDIR)/$(LIBNAME): $(OBJS)
	$(CXX) $(SHARED) $(LDFLAGS) -o $@ $(OBJS)

# The tests are linked against the objects, not against the shared library,
# so that they run without any library search path setup.
$(BUILDDIR)/test_ctph$(EXEEXT): $(BUILDDIR)/test_ctph.o $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(TESTLIBS)

$(BUILDDIR)/test_cluster$(EXEEXT): $(BUILDDIR)/test_cluster.o $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(TESTLIBS)

test: tests
	$(BUILDDIR)/test_ctph$(EXEEXT)
	$(BUILDDIR)/test_cluster$(EXEEXT)

bench: tests
	$(BUILDDIR)/test_ctph$(EXEEXT) --bench

sanitizer:
	$(MAKE) BUILDDIR=build-asan \
	        CXXFLAGS="$(CXXFLAGS) -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined" test

clean:
	-$(RM) $(BUILDDIR)
	-$(RM) build-asan
