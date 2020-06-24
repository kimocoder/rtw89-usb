// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include <linux/bcd.h>

#include "core.h"
#include "reg.h"
#include "fw.h"
#include "debug.h"
#include "mac.h"
#include "phy.h"

#define RTW89_DONT_CARE_8852A 0xFF
#define RTW89_RFREG_MASK 0xFFFFF

struct rtw89_phy_cfg_pair {
	u32 addr;
	u32 data;
};

union rtw89_phy_table_tile {
	struct rtw89_phy_cond cond;
	struct rtw89_phy_cfg_pair cfg;
};

union rtw89_phy_table_tile1 {
	struct rtw89_phy_cond1 cond;
	struct rtw89_phy_cfg_pair cfg;
};

int rtw89_halrf_send_h2c(struct rtw89_dev *rtwdev,
			  u8 *buf, u16 len, u8 cl, u8 func)
{
	struct rtw89_fw_info *fw_info = &rtwdev->fw;
	bool is_fwdl = false;
	int ret;

	rtwdev->debug = true;

	ret = rtw89_mac_send_h2c(rtwdev, buf, len,
				 RTW89_FWCMD_H2C_CAT_OUTSRC,
				 cl, func, is_fwdl);
	if (ret)
		rtw89_err(rtwdev, "fail to send h2c\n");

	fw_info->h2c_seq++;

	rtwdev->debug = false;
	return ret;
}

void rtw89_phy_cfg_bb(struct rtw89_dev *rtwdev, const struct rtw89_table *tbl,
		      u32 addr, u32 data)
{
	if (addr == 0xfe)
		msleep(50);
	else if (addr == 0xfd)
		mdelay(5);
	else if (addr == 0xfc)
		mdelay(1);
	else if (addr == 0xfb)
		usleep_range(50, 60);
	else if (addr == 0xfa)
		udelay(5);
	else if (addr == 0xf9)
		udelay(1);
	else {
		//pr_info("[BB][REG][0]0x%04X = 0x%08X\n", addr, data);
		rtw89_write32(rtwdev, addr | RTW89_BB_OFST, data);
	}
}

static bool rtw89_phy_write_rf(struct rtw89_dev *rtwdev,
			       enum rtw89_rf_path path,
			       u32 addr, u32 mask, u32 data)
{
	u32 direct_addr = 0;
	u32 offset_write_rf[2] = {0xc000, 0xd000};

	if (path > RF_PATH_B) {
		rtw89_err(rtwdev, "fail to write rf: path(%d)\n", path);
		return false;
	}

	addr &= 0xff;
	direct_addr = offset_write_rf[path] + (addr << 2);
	mask &= 0xfffff;

	rtw89_write32_mask(rtwdev, direct_addr | RTW89_BB_OFST, mask, data);
	udelay(1);

	return true;
}

static void rtw89_halrf_radio_store_reg(struct rtw89_dev *rtwdev,
					enum rtw89_rf_path path,
					u32 addr, u32 data)
{
	struct rtw89_halrf_radio_info *radio = &rtwdev->rf.radio_info;
	u32 page, idx, val32;

	val32 = cpu_to_le32((addr << 20) | data);
	switch (path) {
	case RF_PATH_A:
		page = radio->write_times_a / 512;
		idx = radio->write_times_a % 512;
		radio->radio_a_parameter[page][idx] = val32;
		radio->write_times_a++;
		break;
	case RF_PATH_B:
		page = radio->write_times_b / 512;
		idx = radio->write_times_b % 512;
		radio->radio_b_parameter[page][idx] = val32;
		radio->write_times_b++;
		break;
	case RF_PATH_C:
	case RF_PATH_D:
	default:
		break;
	}
}

static void rtw89_halrf_radio_config_to_fw(struct rtw89_dev *rtwdev,
					   enum rtw89_rf_path path)
{
	struct rtw89_halrf_radio_info *radio = &rtwdev->rf.radio_info;
	u16 len;

	if (path == RF_PATH_A) {
		rtw89_halrf_send_h2c(rtwdev, (u8 *)radio->radio_a_parameter[0],
				     512, 8, RTW89_FWCMD_H2C_RADIO_A_INIT_0);
		rtw89_halrf_send_h2c(rtwdev, (u8 *)radio->radio_a_parameter[1],
				     512, 8, RTW89_FWCMD_H2C_RADIO_A_INIT_1);
		len = radio->write_times_a % 512;
		rtw89_halrf_send_h2c(rtwdev, (u8 *)radio->radio_a_parameter[2],
				     len, 8, RTW89_FWCMD_H2C_RADIO_A_INIT_2);
	} else if (path == RF_PATH_B) {
		rtw89_halrf_send_h2c(rtwdev, (u8 *)radio->radio_b_parameter[0],
				     512, 8, RTW89_FWCMD_H2C_RADIO_B_INIT_0);
		rtw89_halrf_send_h2c(rtwdev, (u8 *)radio->radio_b_parameter[1],
				     512, 8, RTW89_FWCMD_H2C_RADIO_B_INIT_1);
		len = radio->write_times_b % 512;
		rtw89_halrf_send_h2c(rtwdev, (u8 *)radio->radio_b_parameter[2],
				     len, 8, RTW89_FWCMD_H2C_RADIO_B_INIT_2);
	} else {
		rtw89_err(rtwdev, "fail to set radio, path:%d\n", path);
		return;
	}

}


void rtw89_phy_cfg_rf(struct rtw89_dev *rtwdev, const struct rtw89_table *tbl,
		      u32 addr, u32 data)
{
	if (addr == 0xfe)
		msleep(50);
	else if (addr == 0xfd)
		mdelay(5);
	else if (addr == 0xfc)
		mdelay(1);
	else if (addr == 0xfb)
		usleep_range(50, 60);
	else if (addr == 0xfa)
		udelay(5);
	else if (addr == 0xf9)
		udelay(1);
	else {
		rtw89_phy_write_rf(rtwdev, tbl->rf_path, addr, RTW89_RFREG_MASK,
				   data);
		rtw89_halrf_radio_store_reg(rtwdev, tbl->rf_path, addr, data);
	}

	//if (tbl->rf_path == RF_PATH_B)
	//	pr_info("[RF][RF_b] %08X %08X\n", addr, data);
}

static bool check_positive(struct rtw89_dev *rtwdev,
			   struct rtw89_phy_cond1 cond)
{
	u32 cut_ver = 15;
	u32 pkg_type = 0;
	u32 rfe_type = 0;

	pr_info("%s cut:0x%08X, pkg:0x%08X, rfe:0x%08X\n", __func__, cond.cut,
		cond.pkg, cond.rfe);
	if (cond.cut && cond.cut != cut_ver)
		return false;

	if (cond.pkg && cond.pkg != pkg_type)
		return false;

	if (cond.rfe && cond.rfe != rfe_type)
		return false;

	return true;
}


void rtw89_parse_tbl_phy_cond1(struct rtw89_dev *rtwdev,
			    const struct rtw89_table *tbl)
{
	const union rtw89_phy_table_tile1 *p = tbl->data;
	const union rtw89_phy_table_tile1 *end = p + tbl->size / 2;
	struct rtw89_phy_cond1 pos_cond = {0};
	struct rtw89_halrf_radio_info *radio = &rtwdev->rf.radio_info;
	bool is_matched = true, is_skipped = false;

	BUILD_BUG_ON(sizeof(union rtw89_phy_table_tile1) !=
		     sizeof(struct rtw89_phy_cfg_pair));

	switch (tbl->rf_path) {
	case RF_PATH_A:
		radio->write_times_a = 0;
		break;
	case RF_PATH_B:
		radio->write_times_b = 0;
		break;
	case RF_PATH_C:
	case RF_PATH_D:
	default:
		break;
	}

	for (; p < end; p++) {
		if (p->cond.pos) {
			switch (p->cond.branch) {
			case BRANCH_ENDIF:
				is_matched = true;
				is_skipped = false;
				break;
			case BRANCH_ELSE:
				is_matched = is_skipped ? false : true;
				break;
			case BRANCH_IF:
			case BRANCH_ELIF:
			default:
				pos_cond = p->cond;
				break;
			}
		} else if (p->cond.neg) {
			if (!is_skipped) {
				if (check_positive(rtwdev, pos_cond)) {
					is_matched = true;
					is_skipped = true;
				} else {
					is_matched = false;
					is_skipped = false;
				}
			} else
				is_matched = false;
		} else if (is_matched)
			(*tbl->do_cfg)(rtwdev, tbl, p->cfg.addr, p->cfg.data);
	}
	rtw89_halrf_radio_config_to_fw(rtwdev, tbl->rf_path);
}

void rtw89_parse_tbl_phy_cond(struct rtw89_dev *rtwdev,
			      const struct rtw89_table *tbl)
{
	u32 cut = 0;
	u32 rfe_type = 0;
	u32 cut_curr = 0;
	u32 rfe_type_curr = 64;
	u32 cut_max = 0;
	const union rtw89_phy_table_tile *p = tbl->data;
	const union rtw89_phy_table_tile *end = p + tbl->size / 2;
	bool is_matched = true, is_skipped = false;
	bool is_rfe_match = false;
	bool is_cut_match = false;
	bool is_else_case = false;
	bool is_rfe_ever_match = false;
	const union rtw89_phy_table_tile *latest_rfe_match_entry, *j;

	BUILD_BUG_ON(sizeof(union rtw89_phy_table_tile) !=
		     sizeof(struct rtw89_phy_cfg_pair));

	for (; p < end; p++) {
		if (p->cond.pos) {
			if (p->cond.branch == BRANCH_ENDIF) {
				is_matched = true;
				is_skipped = false;
			} else {
				if (p->cond.rfe == RTW89_DONT_CARE_8852A) {
					is_rfe_match = true;
				} else {
					rfe_type = p->cond.rfe;
					is_rfe_match = (rfe_type ==
							rfe_type_curr);
				}

				if (p->cond.cut == RTW89_DONT_CARE_8852A) {
					is_cut_match = true;
				} else {
					cut = p->cond.cut;
					is_cut_match = (cut == cut_curr);
				}

				if (p->cond.branch == BRANCH_ELSE) {
					is_else_case = is_skipped ? false
								  : true;
					if (!is_rfe_ever_match) {
						is_matched = is_skipped ? false
									: true;
					}
				}
			}
		} else if (p->cond.neg) {
			if (!is_skipped) {
				if (is_rfe_match && is_cut_match) {
					is_matched = true;
					is_skipped = true;
				} else {
					is_matched = false;
					is_skipped = false;
				}
			} else {
				is_matched = false;
			}
		} else {
			if (is_matched) {
				(*tbl->do_cfg)(rtwdev, tbl, p->cfg.addr,
					       p->cfg.data);
				is_rfe_match = false;
				is_else_case = false;
				is_rfe_ever_match = false;
			} else if (is_rfe_match) {
				if (cut >= cut_max) {
					cut_max = cut;
					is_rfe_ever_match = true;
					latest_rfe_match_entry = p;
				}
			} else if (is_else_case) {
				is_else_case = false;
				is_rfe_ever_match = false;
				is_rfe_match = false;

				j = latest_rfe_match_entry;
				for (; j < end; j++) {
					(*tbl->do_cfg)(rtwdev, tbl, j->cfg.addr,
						       j->cfg.data);
					if (j->cond.pos || j->cond.neg)
						break;
				}
			}
		}
	}
}

static void rtw89_phy_reset(struct rtw89_dev *rtwdev)
{
	/* PHY 0 */
	rtw89_write32(rtwdev, 0x804 | RTW89_BB_OFST, 0xFF);
	rtw89_write32(rtwdev, 0x804 | RTW89_BB_OFST, 0x0);
	rtw89_write32(rtwdev, 0x804 | RTW89_BB_OFST, 0xFF);
	/* PHY 1 */
	rtw89_write32(rtwdev, 0x884 | RTW89_BB_OFST, 0xFF);
	rtw89_write32(rtwdev, 0x884 | RTW89_BB_OFST, 0x0);
	rtw89_write32(rtwdev, 0x884 | RTW89_BB_OFST, 0xFF);
}

void rtw89_phy_load_tables(struct rtw89_dev *rtwdev)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	const struct rtw89_table *tbl;

	//pr_info("%s: bb_tbl\n", __func__);
	//rtw89_load_table(rtwdev, chip->bb_tbl);
	pr_info("%s: phy reset \n", __func__);
	rtw89_phy_reset(rtwdev);
	pr_info("%s: load table radio A \n", __func__);
	tbl = chip->rf_tbl[RF_PATH_A];
	rtw89_load_table(rtwdev, tbl);
	pr_info("%s: load table radio B \n", __func__);
	tbl = chip->rf_tbl[RF_PATH_B];
	rtw89_load_table(rtwdev, tbl);
}