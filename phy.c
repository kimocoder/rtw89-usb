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

#define RTW89_BB_OFST 0x10000

#define RTW89_DONT_CARE_8852A 0xFF
#define RTW89_RFREG_MASK 0xFFFFF

const u32 array_dack_init_8852a[] = {
	0x00, 0x0030EB41,
	0x04, 0x04000000,
	0x08, 0x00000000,
	0x0c, 0x00000000,
	0x10, 0xa2000001,
	0x14, 0x00000000,
	0x18, 0x00000000,
	0x1c, 0x00000000,
	0x20, 0x00000000,
	0x24, 0x00000000,
	0x30, 0x00000000,
	0x50, 0x0030EB41,
	0x54, 0x04000000,
	0x58, 0x00000000,
	0x5c, 0x00000000,
	0x60, 0xa2000001,
	0x64, 0x00000000,
	0x68, 0x00000000,
	0x6c, 0x00000000,
	0x70, 0x00000000,
	0x74, 0x00000000
};

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

static inline u32 rtw89_bb_read32(struct rtw89_dev *rtwdev, u32 addr)
{
	return rtw89_read32(rtwdev, addr | RTW89_BB_OFST);
}


static void rtw89_phy_bb_recover(struct rtw89_dev *rtwdev, u32 addr, u32 data);

static inline void rtw89_bb_write32(struct rtw89_dev *rtwdev,
				    u32 addr, u32 data)
{
	addr |= RTW89_BB_OFST;
	rtw89_write32(rtwdev, addr, data);
	rtw89_phy_bb_recover(rtwdev, addr, data);
}

static inline void rtw89_bb_write32_set(struct rtw89_dev *rtwdev,
					u32 addr, u32 bit)
{
	u32 data;

	addr |= RTW89_BB_OFST;
	rtw89_write32_set(rtwdev, addr, bit);
	data = rtw89_read32(rtwdev, addr);
	rtw89_phy_bb_recover(rtwdev, addr, data);
}

static inline void rtw89_bb_write32_clr(struct rtw89_dev *rtwdev,
					u32 addr, u32 bit)
{
	u32 data;

	addr |= RTW89_BB_OFST;
	rtw89_write32_clr(rtwdev, addr, bit);
	data = rtw89_read32(rtwdev, addr);
	rtw89_phy_bb_recover(rtwdev, addr, data);
}

/* rtw89_bb_write32 */
static void rtw89_phy_rf_dack_reload_by_path(struct rtw89_dev *rtwdev,
					     enum rtw89_rf_path path, u8 index)
{
	u32 reg, val, reg_offset, idx_offset, path_offset;
	int i;

	pr_info("%s: need to set msbk_d\n", __func__);

	idx_offset = (!index) ? 0 : 0x50;
	path_offset = (RF_PATH_A == path) ? 0 : 0x100;

	reg_offset = idx_offset + path_offset;

	/* msbk_id: 15/14/13/12 */
	val = 0;
	for (i = 0; i < 4; i++)
		val |= rtwdev->msbk_d[path][index][i + 12] << (i * 8);
	reg = 0x4c14 + reg_offset;
	rtw89_bb_write32(rtwdev, reg, val);

	/* msbk_id: 11/10/9/8 */
	val = 0;
	for (i = 0; i < 4; i++)
		val |= rtwdev->msbk_d[path][index][i + 8] << (i * 8);
	reg = 0x4c18 + reg_offset;
	rtw89_bb_write32(rtwdev, reg, val);

	/* msbk_id: 7/6/5/4 */
	val = 0;
	for (i = 0; i < 4; i++)
		val |= rtwdev->msbk_d[path][index][i + 4] << (i * 8);
	reg = 0x4c1c + reg_offset;
	rtw89_bb_write32(rtwdev, reg, val);

	/* msbk_id: 3/2/1/0 */
	val = 0;
	for (i = 0; i < 4; i++)
		val |= rtwdev->msbk_d[path][index][i] << (i * 8);
	reg = 0x4c20 + reg_offset;
	rtw89_bb_write32(rtwdev, reg, val);

	val = (rtwdev->biask_d[path][index] << 22) |
	      (rtwdev->dadck_d[path][index] << 14);
	reg = 0x4c24 + reg_offset;
	rtw89_bb_write32(rtwdev, reg, val);
}

static void rtw89_phy_rf_dack_reload(struct rtw89_dev *rtwdev)
{
	u32 val_4cb8_orig, val_4db8_orig;
	int i;

	val_4cb8_orig = rtw89_bb_read32(rtwdev, 0x4cb8);
	val_4db8_orig = rtw89_bb_read32(rtwdev, 0x4db8);

	rtw89_bb_write32_clr(rtwdev, 0x0b2c, BIT(31));
	/* step 1 */
	rtw89_bb_write32_set(rtwdev, 0x4c00, BIT(3));
	rtw89_bb_write32_set(rtwdev, 0x4c50, BIT(3));
	rtw89_bb_write32_set(rtwdev, 0x4cb8, BIT(30));
	rtw89_bb_write32_set(rtwdev, 0x4db8, BIT(30));

	rtw89_bb_write32_set(rtwdev, 0x4ce0, BIT(19));
	rtw89_bb_write32_clr(rtwdev, 0x4de0, BIT(19));

	for (i = 0; i < 2; i++)
		rtw89_phy_rf_dack_reload_by_path(rtwdev, RF_PATH_A, i);

	rtw89_bb_write32_set(rtwdev, 0x4c10, BIT(31));
	rtw89_bb_write32_set(rtwdev, 0x4c60, BIT(31));
	rtw89_bb_write32_clr(rtwdev, 0x4c00, BIT(3));
	rtw89_bb_write32_clr(rtwdev, 0x4c50, BIT(3));
	/* step 2 */
	rtw89_bb_write32_clr(rtwdev, 0x4ce0, BIT(19));
	rtw89_bb_write32_set(rtwdev, 0x4c00, BIT(3));
	rtw89_bb_write32_set(rtwdev, 0x4c50, BIT(3));
	rtw89_bb_write32_clr(rtwdev, 0x4c10, BIT(31));
	rtw89_bb_write32_clr(rtwdev, 0x4c60, BIT(31));
	rtw89_bb_write32_set(rtwdev, 0x4de0, BIT(19));
	/* step 3 */
	for (i = 0; i < 2; i++)
		rtw89_phy_rf_dack_reload_by_path(rtwdev, RF_PATH_B, i);
	rtw89_bb_write32_set(rtwdev, 0x4d10, BIT(31));
	rtw89_bb_write32_set(rtwdev, 0x4d60, BIT(31));
	rtw89_bb_write32_clr(rtwdev, 0x4d00, BIT(3));
	rtw89_bb_write32_clr(rtwdev, 0x4d50, BIT(3));
	/* step 4 */
	rtw89_bb_write32_set(rtwdev, 0x4ce0, BIT(19));

	rtw89_bb_write32(rtwdev, 0x4cb8, val_4cb8_orig);
	rtw89_bb_write32(rtwdev, 0x4db8, val_4db8_orig);
}

static void rtw89_phy_rf_dack_recover(struct rtw89_dev *rtwdev,
				      u8 offset, u32 val)
{
	u32 array_len = sizeof(array_dack_init_8852a) / sizeof(u32);
	u32 *array = (u32 *)array_dack_init_8852a;
	u32 v1 = 0, v2 = 0;
	int i = 0;

	while ((i + 1) < array_len) {
		v1 = array[i];
		v2 = array[i + 1];

		if (offset == v1) {
			rtw89_bb_write32(rtwdev, 0x4c00 | offset, v2);

			/* halrf_dac_cal_8852a */
			if ((!rtwdev->dack_done) &&
			    ((offset == 0x10) || (offset == 0x60)))
				rtw89_bb_write32(rtwdev,
						 0x4c00 | offset, 0x22000001);

			if (((offset == 0x0) &&
			     ((!(val & BIT(0))) || (val & BIT(1))) &&
			     (val != 0x1) && (val != 0x11)) ||
			    ((offset == 0x50) && (val & BIT(1)))) {
				rtw89_bb_write32(rtwdev, 0x4c00, 0x0030EB40);
				rtw89_bb_write32(rtwdev, 0x4c00, 0x0030EB41);
				rtw89_bb_write32(rtwdev, 0x3800, 0x01);
				rtw89_bb_write32(rtwdev, 0x3800, 0x11);
				rtw89_bb_write32(rtwdev, 0x3880, 0x01);
				rtw89_bb_write32(rtwdev, 0x3880, 0x11);
			}

			break;
		}

		i += 2;
	}

	if (!rtwdev->dack_done)
		return;

	if (((offset == 0x0) &&
	     ((!(val & BIT(0))) || (val & BIT(1)) || (val & BIT(3))) &&
	     (val != 0x1) && (val != 0x11)) ||
	    ((offset == 0x50) && ((val & BIT(1)) || (val & BIT(3)))))
		rtw89_phy_rf_dack_reload(rtwdev);
}

static void rtw89_phy_bb_recover(struct rtw89_dev *rtwdev, u32 addr, u32 data)
{
	u8 offset;

	/* exclude mac register range */
	if (addr <= 0xffff)
		return;

	/* exclude rf dac register range */
	if(addr >= 0x14c00 && offset <= 0x14dff)
		return;

	addr &= 0xFFFFFFFC;
	offset = (u8)(addr & 0xFF);
	if (offset <= 0x9F)
		rtw89_phy_rf_dack_recover(rtwdev, offset, data);
}

int rtw89_halrf_send_h2c(struct rtw89_dev *rtwdev,
			  u8 *buf, u16 len, u8 cl, u8 func)
{
	struct rtw89_fw_info *fw_info = &rtwdev->fw;
	bool is_fwdl = false;
	int ret;

	ret = rtw89_mac_send_h2c(rtwdev, buf, len,
				 RTW89_FWCMD_H2C_CAT_OUTSRC,
				 cl, func, is_fwdl);
	if (ret)
		rtw89_err(rtwdev, "fail to send h2c\n");

	fw_info->h2c_seq++;

	return ret;
}
void rtw89_phy_cfg_bb(struct rtw89_dev *rtwdev, const struct rtw89_table *tbl,
		      u32 addr, u32 data)
{
	switch (addr) {
	case 0xfe:
		mdelay(50);
		break;
	case 0xfd:
		mdelay(5);
		break;
	case 0xfc:
		mdelay(1);
		break;
	case 0xfb:
		udelay(50);
		break;
	case 0xfa:
		udelay(5);
		break;
	case 0xf9:
		udelay(1);
		break;
	default:
		//pr_info("[BB][REG][0]0x%04X = 0x%08X\n", addr, data);
		rtw89_bb_write32(rtwdev, addr | RTW89_BB_OFST, data);
		break;
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
		mdelay(50);
	else if (addr == 0xfd)
		mdelay(5);
	else if (addr == 0xfc)
		mdelay(1);
	else if (addr == 0xfb)
		udelay(50);
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
			if (is_skipped) {
				is_matched = false;
			} else {
				if (is_rfe_match && is_cut_match) {
					is_matched = true;
					is_skipped = true;
				} else {
					is_matched = false;
					is_skipped = false;
				}
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
	rtw89_write32_set(rtwdev, 0x804 | RTW89_BB_OFST, 0xFF);
	rtw89_write32_clr(rtwdev, 0x804 | RTW89_BB_OFST, 0xFF);
	rtw89_write32_set(rtwdev, 0x804 | RTW89_BB_OFST, 0xFF);
	/* PHY 1 */
	rtw89_write32_set(rtwdev, 0x884 | RTW89_BB_OFST, 0xFF);
	rtw89_write32_clr(rtwdev, 0x884 | RTW89_BB_OFST, 0xFF);
	rtw89_write32_set(rtwdev, 0x884 | RTW89_BB_OFST, 0xFF);
}

void rtw89_phy_load_tables(struct rtw89_dev *rtwdev)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	const struct rtw89_table *tbl;

	rtwdev->dack_done = false;

	pr_info("%s: bb_tbl\n", __func__);
	rtw89_load_table(rtwdev, chip->bb_tbl);

	pr_info("%s: phy reset \n", __func__);
	rtw89_phy_reset(rtwdev);

	pr_info("%s: load table radio A \n", __func__);
	tbl = chip->rf_tbl[RF_PATH_A];
	rtw89_load_table(rtwdev, tbl);

	pr_info("%s: load table radio B \n", __func__);
	tbl = chip->rf_tbl[RF_PATH_B];
	rtw89_load_table(rtwdev, tbl);
}

