# opentherm_driver
OpenTherm(OT) driver

Checked on Raspberry Pi.
Hardware interface is needed to convert voltage and current levels.
Schematic of the interface used for testing available in opentherm-rpi-interface.pdf.
Uses GPIO 26(in) and 5(out) to thermostat interface and GPIO 20(in) and 21(out) to boiler interface.

# compile and load
make

sudo insmod opentherm.ko

# Usage example

There is simple program in usage-example folder showing how data can be read from the driver.
To compile it simply cd to usage-example and type make.
This driver reads the OT message strips the start and stop bits and 32 bits OT message can be read from the
special devices in /dev

/dev/opentherm0 should be used to read messages coming from the thermostat.
/dev/opentherm2 should be used to read messages coming from the boiler.

The drivers supports blocking and non blocking reads.

Similar approach is for writing data. 32 bits OT messages can be send to the thermostat and boiler.

/dev/opentherm1 should be used to write messages to the thermostat
/dev/opentherm3 should be used to write messages to the boiler

The driver adds the start and stop bits and sends the message to the interface.

# opentherm rpi board
![board](doc/otrpiboard.jpg)
