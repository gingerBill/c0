LTO ?= 0
ASAN ?= 0
TSAN ?= 0
UBSAN ?= 0
DEBUG ?= 0
PROFILE ?= 0
SRCDIR ?= .
UNUSED ?= 1

rwildcard = $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))

CC := gcc
CC ?= clang
LD := $(CC)

ifeq ($(DEBUG),1)
	TYPE := debug
else ifeq ($(PROFILE),1)
	TYPE := profile
else
	TYPE := release
endif

BIN := test

OBJDIR := .build/$(TYPE)/objs
DEPDIR := .build/$(TYPE)/deps

# Collect all .c files for build in SRCDIR
SRCS := $(call rwildcard, $(SRCDIR)/, *c)

# Generate object and dependency filenames
OBJS := $(filter %.o,$(SRCS:%.c=$(OBJDIR)/%.o))
DEPS := $(filter %.d,$(SRCS:%.c=$(DEPDIR)/%.d))

CFLAGS := -Wall
CFLAGS += -Wextra
CFLAGS += -std=c11
CFLAGS += -I../lib

ifeq ($(DEBUG),1)
	# Optimize for debugging
	CFLAGS += -O1
	CFLAGS += -g

	# Do not omit frame pointers in debug builds
	CFLAGS += -fno-omit-frame-pointer
else ifeq ($(PROFILE),1)
	# Enable profile options
	CFLAGS += -pg
	CFLAGS += -no-pie

	# Enable debug symbols in profile builds
	CFLAGS += -g

	# Use slightly less aggressive optimizations in profile builds
	CFLAGS += -02
	CFLAGS += -fno-inline-functions
	CFLAGS += -fno-inline-functions-called-once
	CFLAGS += -fno-optimize-sibling-calls
else
	# Disable default C assertions in release builds
	CFLAGS += -DNDEBUG

	# Highest optimization flag in debug builds
	CFLAGS += -O3

	# Don't need these since not interfacing with C++ code
	CFLAGS += -fno-unwind-tables
	CFLAGS += -fno-asynchronous-unwind-tables
	
	# Don't need any stack protection either
	CFLAGS += -fno-stack-protector
	CFLAGS += -fno-stack-check
	ifeq ($(CC),gcc)
		# This is a gcc only option
		CFLAGS += -fno-stack-clash-protection
	endif

	# Disable frame pointers in release builds too except when using ASAN
	ifeq ($(ASAN),1)
		CFLAGS += -fno-omit-frame-pointer
	else
		CFLAGS += -fomit-frame-pointer
	endif
endif

# Give each function and data its own section so the linker can removed unused
# references to such entities
ifeq ($(UNUSED),1)
	CFLAGS += -ffunction-sections
	CFLAGS += -fdata-sections
endif

# Enable LTO if requested. LTO is not supported in debug builds though
ifeq ($(LTO),1)
ifeq ($(DEBUG),0)
	CFLAGS += -flto
endif
endif

# Select various sanitizers for compiler flags
ifeq ($(ASAN),1)
	CFLAGS += -fsanitize=address
endif
ifeq ($(TSAN),1)
	CFLAGS += -fsanitize=thread
endif
ifeq ($(UBSAN),1)
	CFLAGS += -fsanitize=undefined
endif

DEPFLAGS := -MMD
DEPFLAGS += -MP

LDFLAGS := -L../
LDFLAGS += -l:c0.a

# Strip unused symbols, if requested
ifeq ($(UNUSED),1)
	LDFLAGS += -Wl,--gc-sections
endif

# Enable profiling libraries, if requested
ifeq ($(PROFILE),1)
	LDFLAGS += -pg

	# Cannot use position independent code when using gprof
	LDFLAGS += -no-pie
endif

# Enable LTO, if requested
ifeq ($(LTO),1)
	LDFLAGS += -flto
endif

# Select various sanitizers for linker flags
ifeq ($(ASAN),1)
	LDFLAGS += -fsanitize=address
endif
ifeq ($(TSAN),1)
	LDFLAGS += -fsanitize=thread
endif
ifeq ($(UBSAN),1)
	LDFLAGS += -fsanitize=undefined
endif

all: $(BIN)

# Ensure build artifact directories exist
$(DEPDIR):
	@mkdir -p $(addprefix $(DEPDIR)/,$(call uniq,$(dir $(SRCS))))
$(OBJDIR):
	@mkdir -p $(addprefix $(OBJDIR)/,$(call uniq,$(dir $(SRCS))))

$(OBJDIR)/%.o: %.c $(DEPDIR)/%.d | $(OBJDIR) $(DEPDIR)
	$(CC) -MT $@ $(DEPFLAGS) -MF $(DEPDIR)/$*.Td $(CFLAGS) -c -o $@ $<
	@mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d

$(BIN): $(OBJS)
	$(LD) $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -rf $(DEPDIR) $(OBJDIR) $(BIN)

$(DEPS):
include $(wildcard $(DEPS))

.PHONY: clean