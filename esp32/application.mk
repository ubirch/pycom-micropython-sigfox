#
# Copyright (c) 2018, Pycom Limited.
#
# This software is licensed under the GNU GPL version 3 or any
# later version, with permitted additional terms. For more information
# see the Pycom Licence v1.0 document supplied with this file, or
# available at https://www.pycom.io/opensource/licensing
#

APP_INC =  -I.
APP_INC += -I..
APP_INC += -Ihal
APP_INC += -Iutil
APP_INC += -Imods
APP_INC += -Itelnet
APP_INC += -Iftp
APP_INC += -Ilora
APP_INC += -Ilte
APP_INC += -Ican
APP_INC += -Ibootloader
APP_INC += -Ifatfs/src/drivers
APP_INC += -I$(BUILD)
APP_INC += -I$(BUILD)/genhdr
APP_INC += -I$(ESP_IDF_COMP_PATH)/bootloader_support/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bootloader_support/include_priv
APP_INC += -I$(ESP_IDF_COMP_PATH)/mbedtls/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/mbedtls/port/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/driver/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/driver/include/driver
APP_INC += -I$(ESP_IDF_COMP_PATH)/heap/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/esp32
APP_INC += -I$(ESP_IDF_COMP_PATH)/esp32/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/esp_adc_cal/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/soc/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/soc/esp32/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/expat/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/freertos/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/json/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/expat/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/lwip/include/lwip
APP_INC += -I$(ESP_IDF_COMP_PATH)/lwip/include/lwip/port
APP_INC += -I$(ESP_IDF_COMP_PATH)/newlib/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/nvs_flash/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/spi_flash/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/tcpip_adapter/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/log/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/sdmmc/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/vfs/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/device/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/bta/dm
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/bta/hh
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/bta/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/bta/sys/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/stack/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/stack/gatt/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/stack/gap/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/stack/l2cap/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/btcore/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/osi/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/hci/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/gki/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/api/include
APP_INC += -I$(ESP_IDF_COMP_PATH)/bt/bluedroid/btc/include
APP_INC += -I../lib/mp-readline
APP_INC += -I../lib/netutils
APP_INC += -I../lib/fatfs
APP_INC += -I../lib
APP_INC += -I../drivers/sx127x
APP_INC += -I../stmhal

NACL_PATH = $(ESP_IDF_COMP_PATH)/../../example-esp32/components/ubirch-mbed-nacl-cm0/source
APP_INC += -I$(NACL_PATH)/nacl
APP_INC += -I$(NACL_PATH)/nacl/crypto_sign
APP_INC += -I$(NACL_PATH)/nacl/crypto_hash
APP_INC += -I$(NACL_PATH)/nacl/crypto_hashblocks
APP_INC += -I$(NACL_PATH)/nacl/include
APP_INC += -I$(NACL_PATH)/nacl/shared
APP_INC += -I$(NACL_PATH)/randombytes

APP_MAIN_SRC_C = \
	main.c \
	mptask.c \
	serverstask.c \
	pycom_config.c \
	mpthreadport.c \

APP_HAL_SRC_C = $(addprefix hal/,\
	esp32_mphal.c \
	)

APP_LIB_SRC_C = $(addprefix lib/,\
	libm/math.c \
	libm/fmodf.c \
	libm/roundf.c \
	libm/ef_sqrt.c \
	libm/kf_rem_pio2.c \
	libm/kf_sin.c \
	libm/kf_cos.c \
	libm/kf_tan.c \
	libm/ef_rem_pio2.c \
	libm/sf_sin.c \
	libm/sf_cos.c \
	libm/sf_tan.c \
	libm/sf_frexp.c \
	libm/sf_modf.c \
	libm/sf_ldexp.c \
	libm/asinfacosf.c \
	libm/atanf.c \
	libm/atan2f.c \
	mp-readline/readline.c \
	netutils/netutils.c \
	utils/pyexec.c \
	utils/interrupt_char.c \
	fatfs/ff.c \
	fatfs/option/ccsbcs.c \
	)

APP_MODS_SRC_C = $(addprefix mods/,\
	machuart.c \
	machpin.c \
	machrtc.c \
	machspi.c \
	machine_i2c.c \
	machpwm.c \
	machcan.c \
	modmachine.c \
	moduos.c \
	modusocket.c \
	modnetwork.c \
	modwlan.c \
	moduselect.c \
	modutime.c \
	modpycom.c \
	moduqueue.c \
	moduhashlib.c \
	moducrypto.c \
	modued25519.c \
	machtimer.c \
	machtimer_alarm.c \
	machtimer_chrono.c \
	analog.c \
	pybadc.c \
	pybdac.c \
	pybsd.c \
	modussl.c \
	modbt.c \
	modled.c \
	machwdt.c \
	machrmt.c \
	lwipsocket.c \
	machtouch.c \
	)

APP_MODS_LORA_SRC_C = $(addprefix mods/,\
	modlora.c \
	)

APP_STM_SRC_C = $(addprefix stmhal/,\
	bufhelper.c \
	builtin_open.c \
	import.c \
	input.c \
	lexerfatfs.c \
	pybstdio.c \
	)

APP_UTIL_SRC_C = $(addprefix util/,\
	antenna.c \
	gccollect.c \
	help.c \
	mperror.c \
	random.c \
	mpexception.c \
	fifo.c \
	socketfifo.c \
	mpirq.c \
	mpsleep.c \
	timeutils.c \
	)

APP_FATFS_SRC_C = $(addprefix fatfs/src/,\
	drivers/sflash_diskio.c \
	drivers/sd_diskio.c \
	option/syscall.c \
	diskio.c \
	ffconf.c \
	)

APP_LORA_SRC_C = $(addprefix lora/,\
	utilities.c \
	timer-board.c \
	gpio-board.c \
	spi-board.c \
	sx1276-board.c \
	sx1272-board.c \
	board.c \
	)

APP_LIB_LORA_SRC_C = $(addprefix lib/lora/,\
	mac/LoRaMac.c \
	mac/LoRaMacCrypto.c \
	mac/region/Region.c \
	mac/region/RegionAS923.c \
	mac/region/RegionAU915.c \
	mac/region/RegionCommon.c \
	mac/region/RegionEU868.c \
	mac/region/RegionUS915.c \
	system/delay.c \
	system/gpio.c \
	system/timer.c \
	system/crypto/aes.c \
	system/crypto/cmac.c \
	)

APP_SX1272_SRC_C = $(addprefix drivers/sx127x/,\
	sx1272/sx1272.c \
	)

APP_SX1276_SRC_C = $(addprefix drivers/sx127x/,\
	sx1276/sx1276.c \
	)

APP_SIGFOX_SRC_SIPY_C = $(addprefix sigfox/,\
	manufacturer_api.c \
	radio.c \
	ti_aes_128.c \
	timer.c \
	transmission.c \
	modsigfox.c \
	)

APP_SIGFOX_SRC_FIPY_LOPY4_C = $(addprefix sigfox/,\
	manufacturer_api.c \
	radio_sx127x.c \
	ti_aes_128.c \
	timer.c \
	transmission.c \
	modsigfox.c \
	)

APP_SIGFOX_MOD_SRC_C = $(addprefix mods/,\
	modsigfox_api.c \
	)

APP_SIGFOX_TARGET_SRC_C = $(addprefix sigfox/targets/,\
	cc112x_spi.c \
	hal_int.c \
	hal_spi_rf_trxeb.c \
	trx_rf_int.c \
	)

APP_SIGFOX_SPI_SRC_C = $(addprefix lora/,\
	spi-board.c \
	gpio-board.c \
	)

APP_LTE_SRC_C = $(addprefix lte/,\
    lteppp.c \
    )

APP_MODS_LTE_SRC_C = $(addprefix mods/,\
    modlte.c \
    )

APP_TELNET_SRC_C = $(addprefix telnet/,\
	telnet.c \
	)

APP_FTP_SRC_C = $(addprefix ftp/,\
	ftp.c \
	updater.c \
	)

APP_CAN_SRC_C = $(addprefix can/,\
	CAN.c \
	)

BOOT_SRC_C = $(addprefix bootloader/,\
	bootloader.c \
	bootmgr.c \
	mperror.c \
	gpio.c \
	flash_qio_mode.c \
	)

SFX_OBJ =

OBJ = $(PY_O)
ifeq ($(BOARD), $(filter $(BOARD), LOPY FIPY))
OBJ += $(addprefix $(BUILD)/, $(APP_LORA_SRC_C:.c=.o) $(APP_LIB_LORA_SRC_C:.c=.o) $(APP_SX1272_SRC_C:.c=.o) $(APP_MODS_LORA_SRC_C:.c=.o))
endif
ifeq ($(BOARD), $(filter $(BOARD), LOPY4))
OBJ += $(addprefix $(BUILD)/, $(APP_LORA_SRC_C:.c=.o) $(APP_LIB_LORA_SRC_C:.c=.o) $(APP_SX1276_SRC_C:.c=.o) $(APP_MODS_LORA_SRC_C:.c=.o))
endif
ifeq ($(BOARD), $(filter $(BOARD), SIPY))
OBJ += $(addprefix $(BUILD)/, $(APP_SIGFOX_MOD_SRC_C:.c=.o))
endif
ifeq ($(BOARD), $(filter $(BOARD), LOPY4 FIPY))
OBJ += $(addprefix $(BUILD)/, $(APP_SIGFOX_MOD_SRC_C:.c=.o))
endif
ifeq ($(BOARD),$(filter $(BOARD), FIPY GPY))
OBJ += $(addprefix $(BUILD)/, $(APP_LTE_SRC_C:.c=.o) $(APP_MODS_LTE_SRC_C:.c=.o))
endif

OBJ += $(addprefix $(BUILD)/, $(APP_MAIN_SRC_C:.c=.o) $(APP_HAL_SRC_C:.c=.o) $(APP_LIB_SRC_C:.c=.o))
OBJ += $(addprefix $(BUILD)/, $(APP_MODS_SRC_C:.c=.o) $(APP_STM_SRC_C:.c=.o))
OBJ += $(addprefix $(BUILD)/, $(APP_FATFS_SRC_C:.c=.o) $(APP_UTIL_SRC_C:.c=.o) $(APP_TELNET_SRC_C:.c=.o))
OBJ += $(addprefix $(BUILD)/, $(APP_FTP_SRC_C:.c=.o) $(APP_CAN_SRC_C:.c=.o))
OBJ += $(BUILD)/pins.o

BOOT_OBJ = $(addprefix $(BUILD)/, $(BOOT_SRC_C:.c=.o))

# List of sources for qstr extraction
SRC_QSTR += $(APP_MODS_SRC_C) $(APP_UTIL_SRC_C) $(APP_STM_SRC_C)
ifeq ($(BOARD), $(filter $(BOARD), LOPY LOPY4 FIPY))
SRC_QSTR += $(APP_MODS_LORA_SRC_C)
endif
ifeq ($(BOARD), $(filter $(BOARD), SIPY LOPY4 FIPY))
SRC_QSTR += $(APP_SIGFOX_MOD_SRC_C)
endif
ifeq ($(BOARD),$(filter $(BOARD), FIPY GPY))
SRC_QSTR += $(APP_MODS_LTE_SRC_C)
endif

# Append any auto-generated sources that are needed by sources listed in
# SRC_QSTR
SRC_QSTR_AUTO_DEPS +=

BOOT_LDFLAGS = $(LDFLAGS) -T esp32.bootloader.ld -T esp32.rom.ld -T esp32.peripherals.ld -T esp32.bootloader.rom.ld -T esp32.rom.spiram_incompatible_fns.ld

# add the application linker script(s)
APP_LDFLAGS += $(LDFLAGS) -T esp32_out.ld -T esp32.common.ld -T esp32.rom.ld -T esp32.peripherals.ld

# add the application specific CFLAGS
CFLAGS += $(APP_INC) -DMICROPY_NLR_SETJMP=1 -DMBEDTLS_CONFIG_FILE='"mbedtls/esp_config.h"' -DHAVE_CONFIG_H -DESP_PLATFORM
CFLAGS_SIGFOX += $(APP_INC) -DMICROPY_NLR_SETJMP=1 -DMBEDTLS_CONFIG_FILE='"mbedtls/esp_config.h"' -DHAVE_CONFIG_H -DESP_PLATFORM
CFLAGS += -DREGION_AS923 -DREGION_AU915 -DREGION_EU868 -DREGION_US915

# add the application archive, this order is very important
APP_LIBS = -Wl,--start-group $(LIBS) $(BUILD)/application.a -Wl,--end-group -Wl,-EL

BOOT_LIBS = -Wl,--start-group $(B_LIBS) $(BUILD)/bootloader/bootloader.a -Wl,--end-group -Wl,-EL

# debug / optimization options
ifeq ($(BTYPE), debug)
    CFLAGS += -DDEBUG
    CFLAGS_SIGFOX += -DDEBUG
else
    ifeq ($(BTYPE), release)
        CFLAGS += -DNDEBUG
        CFLAGS_SIGFOX += -DNDEBUG
    else
        $(error Invalid BTYPE specified)
    endif
endif

$(BUILD)/bootloader/%.o: CFLAGS += -D BOOTLOADER_BUILD=1
$(BUILD)/bootloader/%.o: CFLAGS_SIGFOX += -D BOOTLOADER_BUILD=1

BOOT_OFFSET = 0x1000
PART_OFFSET = 0x8000
APP_OFFSET  = 0x10000

SHELL    = bash

BOOT_BIN = $(BUILD)/bootloader/bootloader.bin

ifeq ($(BOARD), WIPY)
    APP_BIN = $(BUILD)/wipy.bin
endif
ifeq ($(BOARD), LOPY)
    APP_BIN = $(BUILD)/lopy.bin
endif
ifeq ($(BOARD), LOPY4)
    APP_BIN = $(BUILD)/lopy4.bin
    $(BUILD)/sigfox/radio_sx127x.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/sigfox/timer.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/sigfox/transmission.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/sigfox/targets/%.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/lora/spi-board.o: CFLAGS = $(CFLAGS_SIGFOX)
endif
ifeq ($(BOARD), SIPY)
    APP_BIN = $(BUILD)/sipy.bin
    $(BUILD)/sigfox/radio.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/sigfox/timer.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/sigfox/transmission.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/sigfox/targets/%.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/lora/spi-board.o: CFLAGS = $(CFLAGS_SIGFOX)
endif
ifeq ($(BOARD), GPY)
    APP_BIN = $(BUILD)/gpy.bin
endif
ifeq ($(BOARD), FIPY)
    APP_BIN = $(BUILD)/fipy.bin
    $(BUILD)/sigfox/radio_sx127x.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/sigfox/timer.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/sigfox/transmission.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/sigfox/targets/%.o: CFLAGS = $(CFLAGS_SIGFOX)
    $(BUILD)/lora/spi-board.o: CFLAGS = $(CFLAGS_SIGFOX)
endif

APP_IMG  = $(BUILD)/appimg.bin
PART_CSV = lib/partitions.csv
PART_BIN = $(BUILD)/lib/partitions.bin
PART_BIN_ENCRYPT = $(PART_BIN)_enc
APP_BIN_ENCRYPT = $(APP_BIN)_enc_0x10000
APP_BIN_ENCRYPT_2 = $(APP_BIN)_enc_0x1A0000

ESPPORT ?= /dev/ttyUSB0
ESPBAUD ?= 921600

FLASH_SIZE = detect
ESPFLASHFREQ = 80m
ESPFLASHMODE = dio

PIC_TOOL = $(PYTHON) tools/pypic.py --port $(ESPPORT)
ENTER_FLASHING_MODE = $(PIC_TOOL) --enter
EXIT_FLASHING_MODE = $(PIC_TOOL) --exit

ESPTOOLPY = $(PYTHON) $(IDF_PATH)/components/esptool_py/esptool/esptool.py --chip esp32
ESPTOOLPY_SERIAL = $(ESPTOOLPY) --port $(ESPPORT) --baud $(ESPBAUD) --before no_reset --after no_reset

ESPTOOLPY_WRITE_FLASH  = $(ESPTOOLPY_SERIAL) write_flash -z --flash_mode $(ESPFLASHMODE) --flash_freq $(ESPFLASHFREQ) --flash_size $(FLASH_SIZE)
ESPTOOLPY_ERASE_FLASH  = $(ESPTOOLPY_SERIAL) erase_flash
ESPTOOL_ALL_FLASH_ARGS = $(BOOT_OFFSET) $(BOOT_BIN) $(PART_OFFSET) $(PART_BIN) $(APP_OFFSET) $(APP_BIN)

ESPSECUREPY = $(PYTHON) $(IDF_PATH)/components/esptool_py/esptool/espsecure.py
ESPEFUSE = $(PYTHON) $(IDF_PATH)/components/esptool_py/esptool/espefuse.py --port $(ESPPORT)

# actual command for signing a binary
SIGN_BINARY = $(ESPSECUREPY) sign_data --keyfile $(SECURE_KEY)

# actual command for signing a binary
# it should be used as:
# $(ENCRYPT_BINARY) $(ENCRYPT_0x10000) -o image_encrypt.bin image.bin 
ENCRYPT_BINARY = $(ESPSECUREPY) encrypt_flash_data --keyfile $(ENCRYPT_KEY)
ENCRYPT_0x10000 = --address 0x10000
ENCRYPT_0x1A0000 = --address 0x1A0000

GEN_ESP32PART := $(PYTHON) $(ESP_IDF_COMP_PATH)/partition_table/gen_esp32part.py -q

ifeq ($(TARGET), app)
all: $(APP_BIN)
else
all: $(BOOT_BIN)
endif

.PHONY: all

ifeq ($(SECURE), on)

# add #define CONFIG_FLASH_ENCRYPTION_ENABLE 1 used for Flash Encryption
# it can also be added permanently in sdkconfig.h
CFLAGS += -DCONFIG_FLASH_ENCRYPTION_ENABLED=1

# add #define CONFIG_SECURE_BOOT_ENABLED 1 used for Secure Boot
# it can also be added permanently in sdkconfig.h
CFLAGS += -DCONFIG_SECURE_BOOT_ENABLED=1

# find the configured private key file
ORIG_SECURE_KEY := $(call resolvepath,$(call dequote,$(SECURE_KEY)),$(PROJECT_PATH))

$(ORIG_SECURE_KEY): 
	$(ECHO) "Secure boot signing key '$@' missing. It can be generated using: "
	$(ECHO) "$(ESPSECUREPY) generate_signing_key $(SECURE_KEY)"
	exit 1

# public key name; the name is important 
# because it will go into the elf with symbols having name derived out of this one
SECURE_BOOT_VERIFICATION_KEY = signature_verification_key.bin

# verification key derived from signing key.
$(SECURE_BOOT_VERIFICATION_KEY): $(ORIG_SECURE_KEY)
	$(ESPSECUREPY) extract_public_key --keyfile $< $@

# key used for bootloader digest 
SECURE_BOOTLOADER_KEY = secure-bootloader-key.bin

$(SECURE_BOOTLOADER_KEY): $(ORIG_SECURE_KEY)
	$(ESPSECUREPY) digest_private_key --keyfile $< $@

# the actual digest+bootloader, that needs to be flashed at address 0x0
BOOTLOADER_REFLASH_DIGEST = 	$(BUILD)/bootloader/bootloader-reflash-digest.bin
BOOTLOADER_REFLASH_DIGEST_ENC = $(BOOTLOADER_REFLASH_DIGEST)_enc

ORIG_ENCRYPT_KEY := $(call resolvepath,$(call dequote,$(ENCRYPT_KEY)),$(PROJECT_PATH))
$(ORIG_ENCRYPT_KEY): 
	$(ECHO) "WARNING: Encryption key '$@' missing. It can be created using: "
	$(ECHO) "$(ESPSECUREPY) generate_flash_encryption_key $(ENCRYPT_KEY)"
	exit 1
	
else #ifeq ($(SECURE), on)
SECURE_BOOT_VERIFICATION_KEY = 
SECURE_BOOTLOADER_KEY = 
ORIG_ENCRYPT_KEY = 
endif #ifeq ($(SECURE), on)


ifeq ($(TARGET), boot)
$(BUILD)/bootloader/bootloader.a: $(BOOT_OBJ) sdkconfig.h
	$(ECHO) "AR $@"
	$(Q) rm -f $@
	$(Q) $(AR) cru $@ $^

$(BUILD)/bootloader/bootloader.elf: $(BUILD)/bootloader/bootloader.a $(SECURE_BOOT_VERIFICATION_KEY)
#	$(ECHO) "COPY IDF LIBRARIES $@"
#	$(Q) $(PYTHON) get_idf_libs.py --idflibs $(IDF_PATH)/examples/wifi/scan/build
ifeq ($(SECURE), on)
# unpack libbootloader_support.a, and archive again using the right key for verifying signatures
	$(ECHO) "Inserting verification key $(SECURE_BOOT_VERIFICATION_KEY) in $@"
	$(Q) $(RM) -f ./bootloader/lib/bootloader_support_temp
	$(Q) $(MKDIR)  ./bootloader/lib/bootloader_support_temp
	$(Q) $(CP) ./bootloader/lib/libbootloader_support.a ./bootloader/lib/bootloader_support_temp/
	$(Q) $(CD) bootloader/lib/bootloader_support_temp/ ; pwd ;\
	$(AR) x libbootloader_support.a ;\
	$(RM) -f $(SECURE_BOOT_VERIFICATION_KEY).bin.o ;\
	$(CP) ../../../$(SECURE_BOOT_VERIFICATION_KEY) . ;\
	$(RM) -f $(SECURE_BOOT_VERIFICATION_KEY).bin.o  libbootloader_support.a ;\
	$(OBJCOPY) $(OBJCOPY_EMBED_ARGS) $(SECURE_BOOT_VERIFICATION_KEY) $(SECURE_BOOT_VERIFICATION_KEY).bin.o ;\
	$(AR) cru libbootloader_support.a *.o ;\
	$(CP) libbootloader_support.a ../
	$(Q) $(RM) -rf ./bootloader/lib/bootloader_support_temp 
endif #ifeq ($(SECURE), on)
	$(ECHO) "LINK $(CC) *** $(BOOT_LDFLAGS) *** $(BOOT_LIBS) -o $@"
	$(Q) $(CC) $(BOOT_LDFLAGS) $(BOOT_LIBS) -o $@
	$(Q) $(SIZE) $@

$(BOOT_BIN): $(BUILD)/bootloader/bootloader.elf $(SECURE_BOOTLOADER_KEY) $(ORIG_ENCRYPT_KEY)
	$(ECHO) "IMAGE $@"
	$(Q) $(ESPTOOLPY) elf2image --flash_mode $(ESPFLASHMODE) --flash_freq $(ESPFLASHFREQ) -o $@ $<
ifeq ($(SECURE), on)
	# obtain the bootloader digest
	$(Q) $(ESPSECUREPY) digest_secure_bootloader -k $(SECURE_BOOTLOADER_KEY)  -o $(BOOTLOADER_REFLASH_DIGEST) $@
	$(ECHO) "Encrypt Bootloader digest (for offset 0x0)"
	$(Q) $(ENCRYPT_BINARY) --address 0x0 -o $(BOOTLOADER_REFLASH_DIGEST_ENC) $(BOOTLOADER_REFLASH_DIGEST)
	$(RM) -f $(BOOTLOADER_REFLASH_DIGEST)
	$(MV) -f $(BOOTLOADER_REFLASH_DIGEST_ENC) $(BOOT_BIN)
	$(ECHO) $(SEPARATOR)
	$(ECHO) $(SEPARATOR)
	$(ECHO) "Steps for using Secure Boot and Flash Encryption:"
	$(ECHO) $(SEPARATOR)
	$(ECHO) "* Prerequisites: hold valid keys for Flash Encryption and Secure Boot"
	$(ECHO) "$(ESPSECUREPY) generate_flash_encryption_key $(ENCRYPT_KEY)"
	$(ECHO) "$(ESPSECUREPY) generate_signing_key $(SECURE_KEY)"
	$(ECHO) $(SEPARATOR)
	$(ECHO) "* Flash keys: write encryption and secure boot EFUSEs (Irreversible operation)"
	$(ECHO) "$(ESPEFUSE) burn_key flash_encryption $(ENCRYPT_KEY)"
	$(ECHO) "$(ESPEFUSE) burn_key secure_boot $(SECURE_BOOTLOADER_KEY)"
	$(ECHO) "$(ESPEFUSE) burn_efuse FLASH_CRYPT_CNT"
	$(ECHO) "$(ESPEFUSE) burn_efuse FLASH_CRYPT_CONFIG 0x0F"
	$(ECHO) "$(ESPEFUSE) burn_efuse ABS_DONE_0"
	$(ECHO) $(SEPARATOR)
	$(ECHO) "* Flash: write bootloader_digest + partition + app all encrypted"
	$(ECHO) "Hint: 'make BOARD=$(BOARD) SECURE=on flash' can be used"
	$(ECHO) "$(ESPTOOLPY_WRITE_FLASH) 0x0 $(BOOTLOADER_REFLASH_DIGEST_ENC) $(PART_OFFSET) $(PART_BIN_ENCRYPT) $(APP_OFFSET) $(APP_BIN_ENCRYPT)"
	$(ECHO) $(SEPARATOR)
	$(ECHO) $(SEPARATOR)
endif #ifeq ($(SECURE), on)
else


$(BUILD)/application.a: $(OBJ)
	$(ECHO) "AR $@"
	$(Q) rm -f $@
	$(Q) $(AR) cru $@ $^

$(BUILD)/application.elf: $(BUILD)/application.a $(BUILD)/esp32_out.ld $(SECURE_BOOT_VERIFICATION_KEY)
#	$(ECHO) "COPY IDF LIBRARIES $@"
#	$(Q) $(PYTHON) get_idf_libs.py --idflibs $(IDF_PATH)/examples/wifi/scan/build
ifeq ($(SECURE), on)
# unpack libbootloader_support.a, and archive again using the right key for verifying signatures
	$(ECHO) "Inserting verification key $(SECURE_BOOT_VERIFICATION_KEY) in $@"
	$(Q) $(RM) -rf ./lib/bootloader_support_temp
	$(Q) $(MKDIR)  ./lib/bootloader_support_temp
	$(Q) $(CP) ./lib/libbootloader_support.a ./lib/bootloader_support_temp/
	$(Q) $(CD) lib/bootloader_support_temp/ ; pwd ;\
	$(AR) x libbootloader_support.a ;\
	$(RM) -f $(SECURE_BOOT_VERIFICATION_KEY).bin.o ;\
	$(CP) ../../$(SECURE_BOOT_VERIFICATION_KEY) . ;\
	$(RM) -f $(SECURE_BOOT_VERIFICATION_KEY).bin.o  libbootloader_support.a ;\
	$(OBJCOPY) $(OBJCOPY_EMBED_ARGS) $(SECURE_BOOT_VERIFICATION_KEY) $(SECURE_BOOT_VERIFICATION_KEY).bin.o ;\
	$(AR) cru libbootloader_support.a *.o ;\
	$(CP) libbootloader_support.a ../
	$(Q) $(RM) -rf lib/bootloader_support_temp
endif #ifeq ($(SECURE), on)
	$(ECHO) "LINK $@"
	$(Q) $(CC) $(APP_LDFLAGS) $(APP_LIBS) -o $@
	$(Q) $(SIZE) $@
endif

$(APP_BIN): $(BUILD)/application.elf $(PART_BIN) $(ORIG_ENCRYPT_KEY)
	$(ECHO) "IMAGE $@"
	$(Q) $(ESPTOOLPY) elf2image --flash_mode $(ESPFLASHMODE) --flash_freq $(ESPFLASHFREQ) -o $@ $<
ifeq ($(SECURE), on)
	$(ECHO) "Signing $@"
	$(Q) $(SIGN_BINARY) $@
	$(ECHO) $(SEPARATOR)
	$(ECHO) "Encrypt image into $(APP_BIN_ENCRYPT) (0x10000 offset) and $(APP_BIN_ENCRYPT_2) (0x1A0000 offset)"
	$(Q) $(ENCRYPT_BINARY) $(ENCRYPT_0x10000) -o $(APP_BIN_ENCRYPT) $@
	$(Q) $(ENCRYPT_BINARY) $(ENCRYPT_0x1A0000) -o $(APP_BIN_ENCRYPT_2) $@
	$(ECHO) "Overwrite $(APP_BIN) with $(APP_BIN_ENCRYPT)"
	$(MV) -f $(APP_BIN_ENCRYPT) $(APP_BIN)
	$(ECHO) $(SEPARATOR)
	$(ECHO) $(SEPARATOR)
	$(ECHO) "Steps for using Secure Boot and Flash Encryption:"
	$(ECHO) $(SEPARATOR)
	$(ECHO) "* Prerequisites: hold valid keys for Flash Encryption and Secure Boot"
	$(ECHO) "$(ESPSECUREPY) generate_flash_encryption_key $(ENCRYPT_KEY)"
	$(ECHO) "$(ESPSECUREPY) generate_signing_key $(SECURE_KEY)"
	$(ECHO) $(SEPARATOR)
	$(ECHO) "* Flash keys: write encryption and secure boot EFUSEs (Irreversible operation)"
	$(ECHO) "$(ESPEFUSE) burn_key flash_encryption $(ENCRYPT_KEY)"
	$(ECHO) "$(ESPEFUSE) burn_key secure_boot $(SECURE_BOOTLOADER_KEY)"
	$(ECHO) "$(ESPEFUSE) burn_efuse FLASH_CRYPT_CNT"
	$(ECHO) "$(ESPEFUSE) burn_efuse FLASH_CRYPT_CONFIG 0x0F"
	$(ECHO) "$(ESPEFUSE) burn_efuse ABS_DONE_0"
	$(ECHO) $(SEPARATOR)
	$(ECHO) "* Flash: write bootloader_digest + partition + app all encrypted"
	$(ECHO) "Hint: 'make BOARD=$(BOARD) SECURE=on flash' can be used"
	$(ECHO) "$(ESPTOOLPY_WRITE_FLASH) 0x0 $(BOOTLOADER_REFLASH_DIGEST_ENC) $(PART_OFFSET) $(PART_BIN_ENCRYPT) $(APP_OFFSET) $(APP_BIN_ENCRYPT)"
	$(ECHO) $(SEPARATOR)
	$(ECHO) $(SEPARATOR)
endif # feq ($(SECURE), on)
	
$(BUILD)/esp32_out.ld: $(ESP_IDF_COMP_PATH)/esp32/ld/esp32.ld sdkconfig.h
	$(ECHO) "CPP $@"
	$(Q) $(CC) -I. -C -P -x c -E $< -o $@

flash: $(APP_BIN) $(BOOT_BIN)
	$(ECHO) "Entering flash mode"
	$(Q) $(ENTER_FLASHING_MODE)
	$(ECHO) "Flashing project"
ifeq ($(SECURE), on)
	$(ECHO) $(SEPARATOR)
	$(ECHO) "(Secure boot enabled, so bootloader + digest is flashed)"
	$(ECHO) $(SEPARATOR)
	$(ECHO) "$(Q) $(ESPTOOLPY_WRITE_FLASH) 0x0 $(BOOTLOADER_REFLASH_DIGEST_ENC) $(PART_OFFSET) $(PART_BIN_ENCRYPT) $(APP_OFFSET) $(APP_BIN_ENCRYPT)"
	$(Q) $(ESPTOOLPY_WRITE_FLASH) 0x0 $(BOOTLOADER_REFLASH_DIGEST_ENC) $(PART_OFFSET) $(PART_BIN_ENCRYPT) $(APP_OFFSET) $(APP_BIN_ENCRYPT)
else # ifeq ($(SECURE), on)
	$(ECHO) "$(ESPTOOLPY_WRITE_FLASH) $(ESPTOOL_ALL_FLASH_ARGS)"
	$(Q) $(ESPTOOLPY_WRITE_FLASH) $(ESPTOOL_ALL_FLASH_ARGS)
endif #ifeq ($(SECURE), on)
	$(ECHO) "Exiting flash mode"
	$(Q) $(EXIT_FLASHING_MODE)

erase:
	$(ECHO) "Entering flash mode"
	$(Q) $(ENTER_FLASHING_MODE)
	$(ECHO) "Erasing flash"
	$(Q) $(ESPTOOLPY_ERASE_FLASH)
	$(ECHO) "Exiting flash mode"
	$(Q) $(EXIT_FLASHING_MODE)

$(PART_BIN): $(PART_CSV) $(ORIG_ENCRYPT_KEY)
	$(ECHO) "Building partitions from $(PART_CSV)..."
	$(Q) $(GEN_ESP32PART) $< $@
ifeq ($(SECURE), on)
	$(ECHO) "Signing $@"
	$(Q) $(SIGN_BINARY) $@
	$(ECHO) "Encrypt paritions table image into $(PART_BIN_ENCRYPT) (by default 0x8000 offset)"
	$(Q) $(ENCRYPT_BINARY) --address 0x8000 -o $(PART_BIN_ENCRYPT) $@
endif # ifeq ($(SECURE), on)

show_partitions: $(PART_BIN)
	$(ECHO) "Partition table binary generated. Contents:"
	$(ECHO) $(SEPARATOR)
	$(Q) $(GEN_ESP32PART) $<
	$(ECHO) $(SEPARATOR)

MAKE_PINS = boards/make-pins.py
BOARD_PINS = boards/$(BOARD)/pins.csv
AF_FILE = boards/esp32_af.csv
PREFIX_FILE = boards/esp32_prefix.c
GEN_PINS_SRC = $(BUILD)/pins.c
GEN_PINS_HDR = $(HEADER_BUILD)/pins.h
GEN_PINS_QSTR = $(BUILD)/pins_qstr.h

# Making OBJ use an order-only dependency on the generated pins.h file
# has the side effect of making the pins.h file before we actually compile
# any of the objects. The normal dependency generation will deal with the
# case when pins.h is modified. But when it doesn't exist, we don't know
# which source files might need it.
$(OBJ): | $(GEN_PINS_HDR)

# Call make-pins.py to generate both pins_gen.c and pins.h
$(GEN_PINS_SRC) $(GEN_PINS_HDR) $(GEN_PINS_QSTR): $(BOARD_PINS) $(MAKE_PINS) $(AF_FILE) $(PREFIX_FILE) | $(HEADER_BUILD)
	$(ECHO) "Create $@"
	$(Q)$(PYTHON) $(MAKE_PINS) --board $(BOARD_PINS) --af $(AF_FILE) --prefix $(PREFIX_FILE) --hdr $(GEN_PINS_HDR) --qstr $(GEN_PINS_QSTR) > $(GEN_PINS_SRC)

$(BUILD)/pins.o: $(BUILD)/pins.c
	$(call compile_c)
