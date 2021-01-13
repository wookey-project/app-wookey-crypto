###################################################################
# About the application name and path
###################################################################

# Application name, can be suffixed by the SDK
APP_NAME ?= crypto
# application build directory name
DIR_NAME = crypto

# project root directory, relative to app dir
PROJ_FILES = ../../

# binary, hex and elf file names
BIN_NAME = $(APP_NAME).bin
HEX_NAME = $(APP_NAME).hex
ELF_NAME = $(APP_NAME).elf

# SDK helper Makefiles inclusion
-include $(PROJ_FILES)/m_config.mk
-include $(PROJ_FILES)/m_generic.mk

# application build directory, relative to the SDK BUILD_DIR environment
# variable.
APP_BUILD_DIR = $(BUILD_DIR)/apps/$(DIR_NAME)

###################################################################
# About the compilation flags
###################################################################

# SDK Cflags
CFLAGS := $(APPS_CFLAGS)
# Application CFLAGS...
CFLAGS += -Isrc/ -MMD -MP

###################################################################
# About the link step
###################################################################

# linker options to add the layout file
LDFLAGS += -L$(APP_BUILD_DIR) $(EXTRA_LDFLAGS)
# project's library you whish to use...
LD_LIBS += -laes -lcryp -lstd

ifeq (y,$(CONFIG_STD_DRBG))
LD_LIBS += -lhmac -lsign
endif

ifeq (y,$(CONFIG_TDES_CBC_ESSIV))
LD_LIBS += -ldes
endif

LD_LIBS += -Wl,--no-whole-archive

###################################################################
# okay let's list our source files and generated files now
###################################################################

CSRC_DIR = src
SRC = $(wildcard $(CSRC_DIR)/*.c)
OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
DEP = $(SRC:.c=.d)

# the output directories, that will be deleted by the distclean target
OUT_DIRS = $(dir $(OBJ))

# the ldcript file generated by the SDK
LDSCRIPT_NAME = $(APP_BUILD_DIR)/$(APP_NAME).ld

# first, objects and compilation related
TODEL_CLEAN += $(OBJ) $(DEP) $(LDSCRIPT_NAME)

# the overall target content
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

.PHONY: app

############################################################
# explicit dependency on the application libs and drivers
# compiling the application requires the compilation of its
# dependencies
###########################################################

## library dependencies
LIBDEP := $(BUILD_DIR)/libs/libstd/libstd.a \
          $(BUILD_DIR)/libs/libaes/libaes.a

ifeq (y,$(CONFIG_TDES_CBC_ESSIV))
LIBDEP += $(BUILD_DIR)/libs/libdes/libdes.a
endif

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

###################################################################
# application generic build targets
###################################################################

show:
	@echo
	@echo "\t\tAPP_BUILD_DIR\t=> " $(APP_BUILD_DIR)
	@echo
	@echo "C sources files:"
	@echo "\t\tSRC\t=> " $(SRC)
	@echo "\t\tOBJ\t=> " $(OBJ)
	@echo "\t\tDEP\t=> " $(DEP)
	@echo
	@echo "\t\tCFG\t=> " $(CFLAGS)


all: $(APP_BUILD_DIR) alldeps app




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
