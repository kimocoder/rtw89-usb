// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include "core.h"
#include "reg.h"
#include "debug.h"
#include "efuse.h"

#define RTW89_EFUSE_BANK_WIFI	0

#define RTW89_EFUSE_WAIT_CNT 1000000

static int rtw89_efuse_switch_bank(struct rtw89_dev *rtwdev)
{
	u8 val8;
	u8 bank = RTW89_EFUSE_BANK_WIFI;
	int ret = -EINVAL;

	val8 = rtw89_read8(rtwdev, R_AX_EFUSE_CTRL_1 + 1);
	if (bank == (val8 & B_AX_EF_CELL_SEL_MSK)) {
		pr_info("%s: wifi bank already\n", __func__);
		return 0;
	}

	val8 &= ~B_AX_EF_CELL_SEL_MSK;
	val8 |= bank;
	rtw89_write8(rtwdev, R_AX_EFUSE_CTRL_1 + 1, val8);

	val8 = rtw89_read8(rtwdev, R_AX_EFUSE_CTRL_1 + 1);
	if (bank == (val8 & B_AX_EF_CELL_SEL_MSK)) {
		pr_info("%s: wifi bank already\n", __func__);
		ret = 0;
	} else  {
		rtw89_err(rtwdev, "fail to switch efuse bank to wifi\n");
		ret = -EINVAL;
	}

	return ret;
}

static bool rtw89_efuse_check_autoload(struct rtw89_dev *rtwdev)
{
	if (rtw89_read16(rtwdev, R_AX_SYS_EEPROM_CTRL) & B_AX_AUTOLOAD_SUS)
		return true;
	else
		return false;
}

static int rtw89_efuse_parse_map(struct rtw89_dev *rtwdev)
{
	u8 *log_map = NULL;
	u8 *phy_map = NULL;
	u32 addr, cnt, val32;
	int log_size = rtwdev->efuse.logical_size;
	int phy_size = rtwdev->efuse.physical_size;
	int ret = -ENOMEM;

	log_map  = kmalloc(log_size, GFP_KERNEL);
	if (!log_map)
		goto out;

	phy_map  = kmalloc(phy_size, GFP_KERNEL);
	if (!phy_map)
		goto out_free_log_map;

	ret = rtw89_efuse_switch_bank(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "fail to switch efuse bank\n");
		goto out_free_phy_map;
	}

	pr_info("%s: phy_size:%u\n", __func__, phy_size);
	for (addr = 0; addr < phy_size; addr++) {
		rtw89_write32(rtwdev, R_AX_EFUSE_CTRL,
			      (addr & B_AX_EF_ADDR_MSK) << B_AX_EF_ADDR_SH);

		cnt = RTW89_EFUSE_WAIT_CNT;
		while (--cnt) {
			val32 = rtw89_read32(rtwdev, R_AX_EFUSE_CTRL);
			if (val32 & B_AX_EF_RDY)
				break;
			udelay(1);
		}

		if (!cnt) {
			rtw89_err(rtwdev, "fail to read efuse\n");
			ret = -EINVAL;
			goto out_free_phy_map;
		}

		phy_map[addr] = (u8)(val32 & 0xFF);
	}

	print_hex_dump(KERN_INFO, "efuse physical: ", DUMP_PREFIX_OFFSET,
		       16, 1, phy_map, phy_size, false);

out_free_phy_map:
	kfree(phy_map);

out_free_log_map:
	kfree(log_map);

out:
	return ret;
}

int rtw89_efuse_process(struct rtw89_dev *rtwdev)
{
	int ret = -EINVAL;

	if (rtw89_efuse_check_autoload(rtwdev))
		pr_info("efuse autoload SUCCESS\n");
	else
		pr_info("efuse autoload FAILED\n");

	ret = rtw89_efuse_parse_map(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "fail to parse efuse map\n");
		return ret;
	}

	return ret;
}

int rtw89_efuse_init(struct rtw89_dev *rtwdev)
{
	int ret = 0;

	rtwdev->efuse.physical_size = rtwdev->chip->physical_size;
	pr_info("%s: physical size: %u\n", __func__, rtwdev->efuse.physical_size);
	rtwdev->efuse.logical_size = rtwdev->chip->log_efuse_size;
	pr_info("%s: logical size: %u\n", __func__, rtwdev->efuse.logical_size);

	return ret;
}

