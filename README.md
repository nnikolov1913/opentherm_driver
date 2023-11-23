# opentherm_driver
OpenTherm driver

Checked on Raspberry Pi.
Hardware interface is needed to convert voltage and current levels.
For example some arduino shields are available and can be used for this purpose.
Uses GPIO 26(in) and 5(out) to thermostat interface and GPIO 20(in) and 21(out) to boiler interface.

# compile and load
make

sudo insmod opentherm.ko
