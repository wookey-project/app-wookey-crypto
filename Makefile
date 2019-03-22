APP_NAME ?= crypto
DIR_NAME = crypto

PROJ_FILES = ../../
BIN_NAME = $(APP_NAME).bin
HEX_NAME = $(APP_NAME).hex
ELF_NAME = $(APP_NAME).elf

######### Metadata ##########
ifeq ($(APP_NAME),crypto)
    IMAGE_TYPE = IMAGE_TYPE0
else
    IMAGE_TYPE = IMAGE_TYPE1
endif

VERSION = 1
#############################

-include $(PROJ_FILES)/Makefile.conf
-include $(PROJ_FILES)/Makefile.gen

# use an app-specific build dir
APP_BUILD_DIR = $(BUILD_DIR)/apps/$(DIR_NAME)

CFLAGS += $(DEBUG_CFLAGS)
CFLAGS += -I$(PROJ_FILES)
CFLAGS += -Isrc/ -Iinc/
CFLAGS += $(APPS_CFLAGS)
CFLAGS += -MMD -MP -O3

LDFLAGS += -fno-builtin -nostdlib -nostartfiles $(AFLAGS_GCC)
#-fno-builtin -nostdlib

EXTRA_LDFLAGS ?= -Tcrypto.fw1.ld
LDFLAGS += -L$(APP_BUILD_DIR) $(EXTRA_LDFLAGS) -fno-builtin -nostdlib
LD_LIBS += -lcryp -laes -lstd -L$(APP_BUILD_DIR)

BUILD_DIR ?= $(PROJ_FILES)build

CSRC_DIR = src
SRC = $(wildcard $(CSRC_DIR)/*.c $(CSRC_DIR)/libaes/*.c $(CSRC_DIR)/libaes/*/*.c)
ASM = $(wildcard $(CSRC_DIR)/libaes/*/*/*.S)
OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
OBJ += $(patsubst %.S,$(APP_BUILD_DIR)/%.o,$(ASM))
DEP = $(SRC:.c=.d)

#Rust sources files
RSSRC_DIR=rust/src
RSRC= $(wildcard $(RSRCDIR)/*.rs)
ROBJ = $(patsubst %.rs,$(APP_BUILD_DIR)/rust/%.o,$(RSRC))

#ada sources files
ASRC_DIR = ada/src
ASRC= $(wildcard $(ASRC_DIR)/*.adb)
AOBJ = $(patsubst %.adb,$(APP_BUILD_DIR)/ada/%.o,$(ASRC))

OUT_DIRS = $(dir $(DRVOBJ)) $(dir $(BOARD_OBJ)) $(dir $(SOC_OBJ)) $(dir $(CORE_OBJ)) $(dir $(AOBJ)) $(dir $(OBJ)) $(dir $(ROBJ))

LDSCRIPT_NAME = $(APP_BUILD_DIR)/$(APP_NAME).ld

# file to (dist)clean
# objects and compilation related
TODEL_CLEAN += $(ROBJ) $(OBJ) $(SOC_OBJ) $(DRVOBJ) $(BOARD_OBJ) $(CORE_OBJ) $(DEP) $(TESTSDEP) $(SOC_DEP) $(DRVDEP) $(BOARD_DEP) $(CORE_DEP) $(LDSCRIPT_NAME)
# targets
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

.PHONY: app

#############################################################
# build targets (driver, core, SoC, Board... and local)
show:
	@echo
	@echo "\t\tAPP_BUILD_DIR\t=> " $(APP_BUILD_DIR)
	@echo
	@echo "C sources files:"
	@echo "\t\tSRC\t=> " $(SRC)
	@echo "\t\tASM\t=> " $(ASM)
	@echo "\t\tOBJ\t=> " $(OBJ)
	@echo "\t\tDEP\t=> " $(DEP)
	@echo
	@echo "\t\tCFG\t=> " $(CFLAGS)


#############################################################

all: $(APP_BUILD_DIR) alldeps app

############################################################
# eplicit dependency on the application libs and drivers
# compiling the application requires the compilation of its
# dependencies
#
## library dependencies
LIBDEP := $(BUILD_DIR)/libs/libstd/libstd.a \
          $(BUILD_DIR)/libs/libstd/libaes.a

libdep: $(LIBDEP)

$(LIBDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)libs/$(patsubst lib%.a,%,$(notdir $@))


# drivers dependencies
SOCDRVDEP := $(BUILD_DIR)/drivers/libcryp/libcryp.a

socdrvdep: $(SOCDRVDEP)

$(SOCDRVDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)drivers/socs/$(SOC)/$(patsubst lib%.a,%,$(notdir $@))

# board drivers dependencies
BRDDRVDEP    :=

brddrvdep: $(BRDDRVDEP)

$(BRDDRVDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)drivers/boards/$(BOARD)/$(patsubst lib%.a,%,$(notdir $@))

# external dependencies
EXTDEP    :=

extdep: $(EXTDEP)

$(EXTDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)externals


alldeps: libdep socdrvdep brddrvdep extdep


app: $(APP_BUILD_DIR)/$(ELF_NAME) $(APP_BUILD_DIR)/$(HEX_NAME)

$(APP_BUILD_DIR)/%.o: %.c
	$(call if_changed,cc_o_c)

$(APP_BUILD_DIR)/%.o: %.S
	$(call if_changed,cc_o_c)

# ELF
$(APP_BUILD_DIR)/$(ELF_NAME): $(ROBJ) $(OBJ) $(SOBJ)
	$(call if_changed,link_o_target)

# HEX
$(APP_BUILD_DIR)/$(HEX_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_ihex)

# BIN
$(APP_BUILD_DIR)/$(BIN_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_bin)

$(APP_BUILD_DIR):
	$(call cmd,mkdir)

-include $(DEP)
