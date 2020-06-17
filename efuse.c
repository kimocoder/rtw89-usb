// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include "core.h"
#include "reg.h"
#include "debug.h"
#include "efuse.h"



bool rtw89_efuse_check_autoload(struct rtw89_dev *rtwdev)
{
	if (rtw89_read16(rtwdev, R_AX_SYS_EEPROM_CTRL) & B_AX_AUTOLOAD_SUS)
		return true;
	else
		return false;
}

int rtw89_parse_efuse_map(struct rtw89_dev *rtwdev)
{
	int ret = -EINVAL;

	pr_info("NEO: TODO: %s ==>\n", __func__);
	return ret;
}


int rtw89_efuse_process(struct rtw89_dev *rtwdev)
{
	int ret = -EINVAL;

	if (rtw89_efuse_check_autoload(rtwdev))
		pr_info("efuse autoload SUCCESS\n");
	else
		pr_info("efuse autoload FAILED\n");

	return ret;
}

