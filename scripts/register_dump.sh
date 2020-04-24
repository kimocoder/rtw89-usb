#!/bin/sh

PHY=phy12
PATH=/sys/kernel/debug/ieee80211/$PHY/rtw89/mac_reg_dump

if [ -z "$2" ]
then
	OUTPUT=$1_dump_registers
else
	OUTPUT=$2
fi

case $1 in
	"mac_all")
		echo mac_00 > $PATH
		/bin/cat $PATH > $OUTPUT
		echo mac_40 > $PATH
		/bin/cat $PATH >> $OUTPUT
		echo mac_80 > $PATH
		/bin/cat $PATH >> $OUTPUT
		echo mac_c0 > $PATH
		/bin/cat $PATH >> $OUTPUT
		;;
	"bb")
		echo bb
		;;
	*)
		echo not matched
		;;
esac

