// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include "core.h"
#include "reg.h"
#include "phy.h"
#include "rtw8852a_table.h"
#include "rtw8852a.h"


static void rtw8852a_enable_bb_rf(struct rtw89_dev *rtwdev, bool enable)
{
	if (enable) {
		rtw89_write8_set(rtwdev, R_AX_SYS_FUNC_EN,
				 B_AX_FEN_BBRSTB | B_AX_FEN_BB_GLB_RSTN);

		rtw89_write32_set(rtwdev, R_AX_WLRF_CTRL,
				  B_AX_WLRF1_CTRL_7 | B_AX_WLRF1_CTRL_1 |
				  B_AX_WLRF_CTRL_7 | B_AX_WLRF_CTRL_1);

		rtw89_write8_set(rtwdev, R_AX_PHYREG_SET,
				 B_AX_PHYREG_SET_ALL_CYCLE);
	} else {
		rtw89_write8_clr(rtwdev, R_AX_SYS_FUNC_EN,
				 B_AX_FEN_BBRSTB | B_AX_FEN_BB_GLB_RSTN);

		rtw89_write32_clr(rtwdev, R_AX_WLRF_CTRL,
				  B_AX_WLRF1_CTRL_7 | B_AX_WLRF1_CTRL_1 |
				  B_AX_WLRF_CTRL_7 | B_AX_WLRF_CTRL_1);

		rtw89_write8_clr(rtwdev, R_AX_PHYREG_SET,
				 B_AX_PHYREG_SET_ALL_CYCLE);
	}
}

static void rtw8852a_reset_bb_rf(struct rtw89_dev *rtwdev)
{
	rtw8852a_enable_bb_rf(rtwdev, 0);
	rtw8852a_enable_bb_rf(rtwdev, 1);
}

static void rtw8852a_phy_set_param(struct rtw89_dev *rtwdev)
{
	rtw8852a_reset_bb_rf(rtwdev);
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
};
EXPORT_SYMBOL(rtw8852a_chip_info);
