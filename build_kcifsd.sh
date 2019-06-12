# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2019 Samsung Electronics Co., Ltd.
#

#!/bin/sh

KERNEL_SRC=''

function is_module
{
	local ok=$(cat "$KERNEL_SRC"/.config | grep -c "CONFIG_CIFS_SERVER=m")

	if [ "z$ok" != "z1" ]; then
		echo "It doesn't look like CIFS_SERVER is as a kernel module"
		exit 1
	fi
}

function patch_fs_config
{
	local ok=$(pwd |  grep -c "fs/cifsd")
	if [ "z$ok" != "z1" ]; then
		echo "ERROR: please ``cd`` to fs/cifsd"
		exit 1
	fi

	KERNEL_SRC=$(pwd | sed -e 's/fs\/cifsd//')
	if [ ! -f "$KERNEL_SRC"/fs/Kconfig ]; then
		echo "ERROR: please ``cd`` to fs/cifsd"
		exit 1
	fi

	ok=$(cat "$KERNEL_SRC"/fs/Makefile | grep cifsd)
	if [ "z$ok" == "z" ]; then
		echo 'obj-$(CONFIG_CIFS_SERVER)	+= cifsd/' \
			>> "$KERNEL_SRC"/fs/Makefile
	fi

	ok=$(cat "$KERNEL_SRC"/fs/Kconfig | grep cifsd)
	if [ "z$ok" == "z" ]; then
		ok=$(cat "$KERNEL_SRC"/fs/Kconfig \
			| sed -e 's/fs\/cifs\/Kconfig/fs\/cifs\/Kconfig\"\nsource \"fs\/cifsd\/Kconfig/' \
			> "$KERNEL_SRC"/fs/Kconfig.new)
		if [ $? != 0 ]; then
			exit 1
		fi
		mv "$KERNEL_SRC"/fs/Kconfig.new "$KERNEL_SRC"/fs/Kconfig
	fi
}

function kcifsd_module_make
{
	echo "Running cifsd make"

	rm cifsd.ko
	cd "$KERNEL_SRC"
	make -C "$KERNEL_SRC" M="$KERNEL_SRC"/fs/cifsd/
	cd "$KERNEL_SRC"/fs/cifsd

	if [ $? != 0 ]; then
		exit 1
	fi
}

function kcifsd_module_install
{
	echo "Running cifsd install"

	local ok=$(lsmod | grep -c cifsd)
	if [ "z$ok" == "z1" ]; then
		sudo rmmod cifsd
		if [ $? -ne 0 ]; then
			echo "ERROR: unable to rmmod cifsd"
			exit 1
		fi
	fi

	is_module

	if [ ! -f "$KERNEL_SRC"/fs/cifsd/cifsd.ko ]; then
		echo "ERROR: cifsd.ko was not found"
		exit 1
	fi

	cd "$KERNEL_SRC"
	if [ -f /lib/modules/$(uname -r)/kernel/fs/cifsd/cifsd.ko ]; then
		sudo rm /lib/modules/$(uname -r)/kernel/fs/cifsd/cifsd.ko*
		sudo cp "$KERNEL_SRC"/fs/cifsd/cifsd.ko \
			/lib/modules/$(uname -r)/kernel/fs/cifsd/cifsd.ko

		local VER=$(make kernelrelease)
		sudo depmod -A $VER
	else
		sudo make -C "$KERNEL_SRC" M="$KERNEL_SRC"/fs/cifsd/ \
			modules_install
		local VER=$(make kernelrelease)
		sudo depmod -A $VER
	fi
	cd "$KERNEL_SRC"/fs/cifsd
}

function kcifsd_module_clean
{
	echo "Running cifsd clean"

	cd "$KERNEL_SRC"
	make -C "$KERNEL_SRC" M="$KERNEL_SRC"/fs/cifsd/ clean
	cd "$KERNEL_SRC"/fs/cifsd
}

patch_fs_config

case $1 in
	clean)
		kcifsd_module_clean
		exit 0
		;;
	install)
		kcifsd_module_make
		kcifsd_module_install
		exit 0
		;;
	modules)
		kcifsd_module_make
		exit 0
		;;
	*)
		kcifsd_module_make
		exit 0
		;;
esac
