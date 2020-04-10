# rtw89-usb

Unofficial Driver for 802.11ax USB Adapter with chipset:
  RTL8852AU

Still under construction, cannot work yet. 

## Build

```console
$ make clean
$ make
```
## Installation

Load driver for test:
```console
$ sudo mkdir -p /lib/firmware/rtw89
$ sudo cp fw/rtw8852* /lib/firmware/rtw89/
$ sudo insmod rtw89_core.ko
$ sudo insmod rtw89_usb.ko
```
Load driver at boot:
```console
$ sudo mkdir -p /lib/firmware/rtw89
$ sudo cp fw/rtw8852* /lib/firmware/rtw89/
$ sudo mkdir /lib/modules/`uname -r`/kernel/drivers/net/wireless/realtek/rtw89
$ sudo cp rtw89_core.ko /lib/modules/`uname -r`/kernel/drivers/net/wireless/realtek/rtw89
$ sudo cp rtw89_usb.ko /lib/modules/`uname -r`/kernel/drivers/net/wireless/realtek/rtw89
$ sudo depmod -a
$ sudo echo -e "rtw89\nrtwusb" > /etc/modules-load.d/rtwusb.conf
$ sudo systemctl start systemd-modules-load
```

## General Commands

Scan:
```console
$ sudo iw wlanX scan
```
Connect to the AP without security:
```console
$ sudo iw wlanX connect <AP name>
```
## Known Issues

