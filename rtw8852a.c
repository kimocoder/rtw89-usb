// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include "core.h"
#include "reg.h"
#include "phy.h"
#include "rtw8852a_table.h"
#include "rtw8852a.h"


static void rtw8852a_phy_set_param(struct rtw89_dev *rtwdev)
{
	pr_info("%s: phy load tables\n", __func__);
	rtw89_phy_load_tables(rtwdev);
}

static const struct rtw89_chip_ops rtw8852a_chip_ops = {
	.phy_set_param = rtw8852a_phy_set_param,
};

const struct rtw89_chip_info rtw8852a_chip_info = {
	.chip_id	= RTL8852A,
	.ops = &rtw8852a_chip_ops,
	.fw_name = "rtw89/rtw8852a_fw.bin",
	.fifo_size = 458752,
	.physical_size = 1216,
	.log_efuse_size = 1536,
	.sec_ctrl_efuse_size = 4,
	.bb_tbl = &rtw8852a_bb_tbl,
	.rf_tbl = {&rtw8852a_rf_a_tbl, &rtw8852a_rf_b_tbl},
};
EXPORT_SYMBOL(rtw8852a_chip_info);
