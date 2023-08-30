# opentherm_driver
OpenTherm driver

Checked on Raspberry Pi.
Hardware interface is needed to convert voltage and current levels.
For example some arduino shields are available and can be used for this purpose.
Uses GPIO23(in) and 22(out) to thermostat interface and GPIO 25(in) and 24(out) to boiler interface.

# compile and load
make

sudo insmod opentherm.ko
