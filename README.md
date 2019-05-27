The MicroPython project
=======================
<p align="center">
  <img src="https://raw.githubusercontent.com/pycom/LoPy/master/images/LopySide.jpg" alt="The LoPy"/>
</p>

This is the MicroPython project, which aims to put an implementation
of Python 3.x on microcontrollers and small embedded systems.
You can find the official website at [micropython.org](http://www.micropython.org).

WARNING: this project is in beta stage and is subject to changes of the
code-base, including project-wide name changes and API changes.

MicroPython implements the entire Python 3.4 syntax (including exceptions,
"with", "yield from", etc., and additionally "async" keyword from Python 3.5).
The following core datatypes are provided: str (including basic Unicode
support), bytes, bytearray, tuple, list, dict, set, frozenset, array.array,
collections.namedtuple, classes and instances. Builtin modules include sys,
time, and struct, etc. Select ports have support for `_thread` module
(multithreading). Note that only subset of Python 3.4 functionality
implemented for the data types and modules.

See the repository www.github.com/micropython/pyboard for the MicroPython
board (PyBoard), the officially supported reference electronic circuit board.

The following components are actively maintained by Pycom:
- py/ -- the core Python implementation, including compiler, runtime, and
  core library.
- exp32/ -- a version of MicroPython that runs on the ESP32 based boards from Pycom.
- tests/ -- test framework and test scripts.

Additional components:
- stmhal/ -- a version of MicroPython that runs on the PyBoard and similar
  STM32 boards (using ST's Cube HAL drivers).
- minimal/ -- a minimal MicroPython port. Start with this if you want
  to port MicroPython to another microcontroller.
- bare-arm/ -- a bare minimum version of MicroPython for ARM MCUs. Used
  mostly to control code size.
- teensy/ -- a version of MicroPython that runs on the Teensy 3.1
  (preliminary but functional).
- pic16bit/ -- a version of MicroPython for 16-bit PIC microcontrollers.
- cc3200/ -- a version of MicroPython that runs on the CC3200 from TI.
- esp8266/ -- an experimental port for ESP8266 WiFi modules.
- tools/ -- various tools, including the pyboard.py module.
- examples/ -- a few example Python scripts.
- docs/ -- user documentation in Sphinx reStructuredText format.

The subdirectories above may include READMEs with additional info.

"make" is used to build the components, or "gmake" on BSD-based systems.
You will also need bash and Python (at least 2.7 or 3.3).

The ESP32 version
-----------------

The "esp32" port requires an xtensa gcc compiler, which can be downloaded from
the Espressif website:

- for 64-bit Linux::

    https://dl.espressif.com/dl/xtensa-esp32-elf-linux64-1.22.0-80-g6c4433a-5.2.0.tar.gz

- for 32-bit Linux::

    https://dl.espressif.com/dl/xtensa-esp32-elf-linux32-1.22.0-80-g6c4433a-5.2.0.tar.gz

- for Mac OS:

    https://dl.espressif.com/dl/xtensa-esp32-elf-osx-1.22.0-80-g6c4433a-5.2.0.tar.gz

To use it, you will need to update your ``PATH`` environment variable in ``~/.bash_profile`` file. To make ``xtensa-esp32-elf`` available for all terminal sessions, add the following line to your ``~/.bash_profile`` file::

    export PATH=$PATH:$HOME/esp/xtensa-esp32-elf/bin

Alternatively, you may create an alias for the above command. This way you can get the toolchain only when you need it. To do this, add different line to your ``~/.bash_profile`` file::

    alias get_esp32="export PATH=$PATH:$HOME/esp/xtensa-esp32-elf/bin"

Then when you need the toolchain you can type ``get_esp32`` on the command line and the toolchain will be added to your ``PATH``.

You also need the ESP IDF along side this repository in order to build the ESP32 port.
To get it:

    $ git clone https://github.com/pycom/pycom-esp-idf.git

After cloning, make sure to checkout all the submodules:

    $ cd pycom-esp-idf
    $ git submodule update --init

Finally, before building, export the IDF_PATH variable

    $ export IDF_PATH=~/pycom-esp-idf
    
This repository contains submodules! Clone using the --recursive option:

    $ git clone --recursive https://github.com/pycom/pycom-micropython-sigfox.git
    
Alternatively checkout the modules manually:

    $ cd pycom-micropython-sigfox
    $ git submodule update --init

``` text
If you updated the repository from a previous revision and/or if switching between branches,<br>
make sure to also update the submodules with the command above.
```

Prior to building the main firmware, you need to build mpy-cross

	$ cd mpy-cross && make clean && make && cd ..

By default the firmware is built for the WIPY2:

    $ cd esp32
    $ make clean
    $ make TARGET=boot
    $ make TARGET=app
    $ make flash

You can change the board type by using the BOARD variable:

    $ cd esp32
    $ make BOARD=GPY clean
    $ make BOARD=GPY TARGET=boot
    $ make BOARD=GPY TARGET=app
    $ make BOARD=GPY flash

We currently support the following BOARD types:

	WIPY LOPY SIPY GPY FIPY LOPY4

For LoRa, you may need to specify the `LORA_BAND` as explained below.

To specify a serial port other than /dev/ttyUSB0, use ESPPORT variable:

    $ # On MacOS
    $ make ESPPORT=/dev/tty.usbserial-DQ008HQY flash
    $ # On Windows
    $ make ESPPORT=COM3 flash
    $ # On linux
    $ # make ESPPORT=/dev/ttyUSB1 flash

To flash at full speed, use ESPSPEED variable:

	$ make ESPSPEED=921600 flash

To build and flash a LoPy:

    $ cd esp32
    $ make BOARD=LOPY clean
    $ make BOARD=LOPY TARGET=boot
    $ make BOARD=LOPY TARGET=app
    $ make BOARD=LOPY flash

The above also applies to the FiPy and LoPy4

Make sure that your board is placed into programming mode, otherwise flashing will fail.<br>
PyTrack and PySense boards will automatically switch into programming mode<br>
(currently supported on MacOS and Linux only!)<br><br>
Expansion Board 2.0 users, please connect ``P2`` to ``GND`` and then reset the board.

## Steps for using Secure Boot and Flash Encryption

### Summary

1. Obtain keys (for Secure Boot and Flash Encryption)
2. Flash keys and parameters in efuses
3. Compile bootloader and application with `make SECURE=on`
4. Flash: bootloader-digest at address 0x0 and encrypted; all the others (partitions and application) encrypted, too.

### Prerequisites

    $ export IDF_PATH=<pycom-esp-idf_PATH>
    $ cd esp32

Hold valid keys for Flash Encryption and Secure Boot; they can be generated randomly with the following commands:

    python $IDF_PATH/components/esptool_py/esptool/espsecure.py generate_flash_encryption_key flash_encryption_key.bin
    python $IDF_PATH/components/esptool_py/esptool/espsecure.py generate_signing_key secure_boot_signing_key.pem

The Secure Boot key `secure_boot_signing_key.pem` has to be transformed into `secure-bootloader-key.bin`, to be burnt into efuses. This can be done in 2 ways:

    python $IDF_PATH/components/esptool_py/esptool/espsecure.py extract_public_key --keyfile secure_boot_signing_key.pem signature_verification_key.bin

    # or, as an artifact of the make build process, on the same directory level as Makefile
    make BOARD=GPY SECURE=on TARGET=boot

Flash keys (`flash_encryption_key.bin` and `secure-bootloader-key.bin`) into the efuses (write and read protected):

**_Note: Irreversible operations_**

    # Burning Encryption Key
    python $IDF_PATH/components/esptool_py/esptool/espefuse.py --port /dev/ttyUSB0 burn_key flash_encryption flash_encryption_key.bin
    # Burning Secure Boot Key
    python $IDF_PATH/components/esptool_py/esptool/espefuse.py --port /dev/ttyUSB0 burn_key secure_boot secure-bootloader-key.bin
    # Enabling Flash Encryption mechanism
    python $IDF_PATH/components/esptool_py/esptool/espefuse.py --port /dev/ttyUSB0 burn_efuse FLASH_CRYPT_CNT
    # Configuring Flash Encryption to use all address bits togheter with Encryption key (max value 0x0F)
    python $IDF_PATH/components/esptool_py/esptool/espefuse.py --port /dev/ttyUSB0 burn_efuse FLASH_CRYPT_CONFIG 0x0F
    # Enabling Secure Boot mechanism
    python $IDF_PATH/components/esptool_py/esptool/espefuse.py --port /dev/ttyUSB0 burn_efuse ABS_DONE_0

**_If the keys are not written in efuse, before flashing the bootloader, then random keys will be generated by the ESP32, they can never be read nor re-written, so bootloader can never be updated. Even more, the application can be re-flashed (by USB) just 3 more times._**

### Makefile options:

    make BOARD=GPY SECURE=on SECURE_KEY=secure_boot_signing_key.pem ENCRYPT_KEY=flash_encryption_key.bin TARGET=[boot|app]

- `SECURE=on` is the main flag; it's not optional
- if `SECURE=on` by default:
    - encryption is enabled        
    - secure_boot_signing_key.pem is the secure boot key, located relatively to Makefile
    - flash_encryption_key.bin is the flash encryption key, located relatively to Makefile

For flashing the bootloader digest and the encrypted versions of all binaries:

    make BOARD=GPY SECURE=on flash

### Flashing

For flashing the bootloader-reflash-digest.bin has to be written at address 0x0, instead of the bootloader.bin (at address 0x1000).

Build is done using `SECURE=on` option; additionally, all the binaries are pre-encrypted.

    make BOARD=GPY clean
    make BOARD=GPY SECURE=on TARGET=boot
    make BOARD=GPY SECURE=on TARGET=app
    make BOARD=GPY SECURE=on flash

Manual flash command:

    python $IDF_PATH/components/esptool_py/esptool/esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 921600 --before no_reset --after no_reset write_flash -z --flash_mode dio --flash_freq 80m --flash_size detect 0x0 build/GPY/release/bootloader/bootloader-reflash-digest.bin_enc 0x8000 build/GPY/release/lib/partitions.bin_enc 0x10000 build/GPY/release/gpy.bin_enc_0x10000

### OTA update

The OTA should be done using the pre-encrypted application image.

Because the encryption is done based on the physical flash address, there are 2 application binaries generated:
- gpy.bin_enc_0x10000 which has to be written at default factory address: 0x10000
- gpy.bin_enc_0x1A0000 which has to be written at the ota_0 partition address (0x1A0000)

*__Hint:__ on micropython interface, the method `pycom.ota_slot()` responds with the address of the next OTA partition available (either 0x10000 or 0x1A0000).*
