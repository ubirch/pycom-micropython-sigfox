# Adding ed25519 support

_use the correct [ESP-IDF](https://github.com/pycom/pycom-esp-idf) for compiling, setting ESP_IDF env variable_

- check out branch feature-ubirch-ed25519
- compile ESP32 ed25519 component https://github.com/ubirch/ubirch-mbed-nacl-cm0
- link libubirch-mbed-nacl-cm0.a into [lib](lib) directory
- run `make BOARD=GPY` (for gPy module)
- run `make BOARD=GPY flash` to flash to module