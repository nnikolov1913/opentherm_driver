# opentherm_driver
OpenTherm driver

Checked on Raspberry Pi.
Hardware interface is needed to convert voltage and current levels.
Schematic of the interface used for testing available in opentherm-rpi-interface.pdf.
Uses GPIO 26(in) and 5(out) to thermostat interface and GPIO 20(in) and 21(out) to boiler interface.

# compile and load
make

sudo insmod opentherm.ko
