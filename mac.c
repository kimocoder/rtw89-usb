// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include "core.h"
#include "debug.h"
#include "reg.h"
#include "fw.h"
#include "pci.h"
#include "efuse.h"
#include "txrx.h"
#include "mac.h"

int rtw89_mac_check_mac_en(struct rtw89_dev *rtwdev, u8 band,
			   enum rtw89_mac_hwmod_sel sel)
{
	u32 val, r_val;

	if (sel == RTW89_DMAC_SEL) {
		r_val = rtw89_read32(rtwdev, R_AX_DMAC_FUNC_EN);
		val = (B_AX_MAC_FUNC_EN | B_AX_DMAC_FUNC_EN);
	} else if (sel == RTW89_CMAC_SEL && band == 0) {
		r_val = rtw89_read32(rtwdev, R_AX_CMAC_FUNC_EN);
		val = B_AX_CMAC_EN;
	} else if (sel == RTW89_CMAC_SEL && band == 1) {
		r_val = rtw89_read32(rtwdev, R_AX_SYS_ISO_CTRL_EXTEND);
		val = B_AX_CMAC1_FEN;
	} else {
		return -EINVAL;
	}
	if (r_val == RTW89_R32_EA || r_val == RTW89_R32_DEAD ||
	    (val & r_val) != val)
		return -EFAULT;

	return 0;
}

static inline u32 rtw89_mac_reg_by_band(u32 reg_base, u8 band)
{
	return band == 0 ? reg_base : (reg_base + 0x2000);
}

static struct rtw89_hfc_ch_info hfc_chinfo[RTW89_DMA_CH_NUM];

static struct rtw89_hfc_pub_info hfc_pubinfo;

static struct rtw89_hfc_param hfc_param = {
	0, /* Enable */
	0, /* H2C Enable */
	0, /* Mode */
	NULL,
	hfc_chinfo,
	NULL,
	&hfc_pubinfo,
	NULL
};

static struct rtw89_hfc_ch_cfg hfc_chcfg_pcie_8852a[] = {
	{128, 1896, grp_0}, /* ACH 0 */
	{128, 1896, grp_0}, /* ACH 1 */
	{128, 1896, grp_0}, /* ACH 2 */
	{128, 1896, grp_0}, /* ACH 3 */
	{128, 1896, grp_1}, /* ACH 4 */
	{128, 1896, grp_1}, /* ACH 5 */
	{128, 1896, grp_1}, /* ACH 6 */
	{128, 1896, grp_1}, /* ACH 7 */
	{32, 1896, grp_0}, /* B0MGQ */
	{128, 1896, grp_0}, /* B0HIQ */
	{32, 1896, grp_1}, /* B1MGQ */
	{128, 1896, grp_1}, /* B1HIQ */
	{40, 0, 0} /* FWCMDQ */
};

static struct rtw89_hfc_ch_cfg hfc_chcfg_pcie_stf_8852a[] = {
	{8, 256, grp_0}, /* ACH 0 */
	{8, 256, grp_0}, /* ACH 1 */
	{8, 256, grp_0}, /* ACH 2 */
	{8, 256, grp_0}, /* ACH 3 */
	{8, 256, grp_1}, /* ACH 4 */
	{8, 256, grp_1}, /* ACH 5 */
	{8, 256, grp_1}, /* ACH 6 */
	{8, 256, grp_1}, /* ACH 7 */
	{8, 256, grp_0}, /* B0MGQ */
	{8, 256, grp_0}, /* B0HIQ */
	{8, 256, grp_1}, /* B1MGQ */
	{8, 256, grp_1}, /* B1HIQ */
	{40, 0, 0} /* FWCMDQ */
};

static struct rtw89_hfc_ch_cfg hfc_chcfg_pcie_sutp_8852a[] = {
	{128, 256, grp_0}, /* ACH 0 */
	{0, 0, grp_1}, /* ACH 1 */
	{0, 0, grp_1}, /* ACH 2 */
	{0, 0, grp_1}, /* ACH 3 */
	{0, 0, grp_1}, /* ACH 4 */
	{0, 0, grp_1}, /* ACH 5 */
	{0, 0, grp_1}, /* ACH 6 */
	{0, 0, grp_1}, /* ACH 7 */
	{0, 0, grp_1}, /* B0MGQ */
	{0, 0, grp_1}, /* B0HIQ */
	{0, 0, grp_1}, /* B1MGQ */
	{0, 0, grp_1}, /* B1HIQ */
	{40, 0, 0} /* FWCMDQ */
};

static struct rtw89_hfc_ch_cfg hfc_chcfg_pcie_bcn_test_8852a[] = {
	{128, 1833, grp_0}, /* ACH 0 */
	{128, 1833, grp_0}, /* ACH 1 */
	{128, 1833, grp_0}, /* ACH 2 */
	{128, 1833, grp_0}, /* ACH 3 */
	{128, 1833, grp_1}, /* ACH 4 */
	{128, 1833, grp_1}, /* ACH 5 */
	{128, 1833, grp_1}, /* ACH 6 */
	{128, 1833, grp_1}, /* ACH 7 */
	{32, 1833, grp_0}, /* B0MGQ */
	{128, 1833, grp_0}, /* B0HIQ */
	{32, 1833, grp_1}, /* B1MGQ */
	{128, 1833, grp_1}, /* B1HIQ */
	{40, 0, 0} /* FWCMDQ */
};

static struct rtw89_hfc_pub_cfg hfc_pubcfg_pcie_8852a = {
	1896, /* Group 0 */
	1896, /* Group 1 */
	3792, /* Public Max */
	0 /* WP threshold */
};

static struct rtw89_hfc_pub_cfg hfc_pubcfg_pcie_stf_8852a = {
	256, /* Group 0 */
	256, /* Group 1 */
	512, /* Public Max */
	104 /* WP threshold */
};

static struct rtw89_hfc_pub_cfg hfc_pubcfg_pcie_sutp_8852a = {
	256, /* Group 0 */
	0, /* Group 1 */
	256, /* Public Max */
	0 /* WP threshold */
};

static struct rtw89_hfc_pub_cfg hfc_pubcfg_pcie_bcn_test_8852a = {
	1833, /* Group 0 */
	1833, /* Group 1 */
	3666, /* Public Max */
	0 /* WP threshold */
};

static struct rtw89_hfc_prec_cfg hfc_preccfg_pcie = {
	1, /*CH 0-11 pre-cost */
	40, /*H2C pre-cost */
	0, /* WP CH 0-7 pre-cost */
	0, /* WP CH 8-11 pre-cost */
	1, /* CH 0-11 full condition */
	0, /* H2C full condition */
	0, /* WP CH 0-7 full condition */
	0 /* WP CH 8-11 full condition */
};

static struct rtw89_hfc_prec_cfg hfc_preccfg_pcie_wd128 = {
	2, /*CH 0-11 pre-cost */
	40, /*H2C pre-cost */
	0, /* WP CH 0-7 pre-cost */
	0, /* WP CH 8-11 pre-cost */
	1, /* CH 0-11 full condition */
	0, /* H2C full condition */
	0, /* WP CH 0-7 full condition */
	0 /* WP CH 8-11 full condition */
};

static struct rtw89_hfc_prec_cfg hfc_preccfg_pcie_stf = {
	1, /*CH 0-11 pre-cost */
	40, /*H2C pre-cost */
	64, /* WP CH 0-7 pre-cost */
	64, /* WP CH 8-11 pre-cost */
	1, /* CH 0-11 full condition */
	0, /* H2C full condition */
	1, /* WP CH 0-7 full condition */
	1 /* WP CH 8-11 full condition */
};


static struct rtw89_hfc_ch_cfg hfc_chcfg_usb_8852a_dbcc[] = {
	{22, 212, grp_0}, /* ACH 0 */
	{0, 0, grp_0}, /* ACH 1 */
	{22, 212, grp_0}, /* ACH 2 */
	{0, 0, grp_0}, /* ACH 3 */
	{22, 212, grp_1}, /* ACH 4 */
	{0, 0, grp_1}, /* ACH 5 */
	{22, 212, grp_1}, /* ACH 6 */
	{0, 0, grp_1}, /* ACH 7 */
	{22, 212, grp_0}, /* B0MGQ */
	{0, 0, grp_0}, /* B0HIQ */
	{22, 212, grp_1}, /* B1MGQ */
	{0, 0, grp_1}, /* B1HIQ */
	{0, 0, 0} /* FWCMDQ */
};

static struct rtw89_hfc_pub_cfg hfc_pubcfg_usb_8852a_dbcc = {
	256, /* Group 0 */
	256, /* Group 1 */
	512, /* Public Max */
	104 /* WP threshold */
};

static struct rtw89_hfc_ch_cfg hfc_chcfg_usb_8852a_scc[] = {
	{22, 402, grp_0}, /* ACH 0 */
	{0, 0, grp_0}, /* ACH 1 */
	{22, 402, grp_0}, /* ACH 2 */
	{0, 0, grp_0}, /* ACH 3 */
	{22, 402, grp_0}, /* ACH 4 */
	{0, 0, grp_0}, /* ACH 5 */
	{22, 402, grp_0}, /* ACH 6 */
	{0, 0, grp_0}, /* ACH 7 */
	{22, 402, grp_0}, /* B0MGQ */
	{0, 0, grp_0}, /* B0HIQ */
	{22, 402, grp_0}, /* B1MGQ */
	{0, 0, grp_0}, /* B1HIQ */
	{0, 0, 0} /* FWCMDQ */
};

static struct rtw89_hfc_pub_cfg hfc_pubcfg_usb_8852a_scc = {
	512, /* Group 0 */
	0, /* Group 1 */
	512, /* Public Max */
	104 /* WP threshold */
};

static struct rtw89_hfc_prec_cfg hfc_preccfg_usb = {
	11, /*CH 0-11 pre-cost */
	32, /*H2C pre-cost */
	25, /* WP CH 0-7 pre-cost */
	25, /* WP CH 8-11 pre-cost */
	1, /* CH 0-11 full condition */
	1, /* H2C full condition */
	1, /* WP CH 0-7 full condition */
	1 /* WP CH 8-11 full condition */
};

static inline struct rtw89_hfc_param *hfc_get_param(void)
{
	return &hfc_param;
}

struct rtw89_hfc_param_ini {
	enum rtw89_qta_mode qta_mode;
	struct rtw89_hfc_ch_cfg *ch_cfg;
	struct rtw89_hfc_pub_cfg *pub_cfg;
	struct rtw89_hfc_prec_cfg *prec_cfg;
	u8 mode;
};

static struct rtw89_hfc_param_ini rtw8852a_hfc_param_ini_pcie[] = {
	{RTW89_QTA_SCC, hfc_chcfg_pcie_8852a,
	 &hfc_pubcfg_pcie_8852a, &hfc_preccfg_pcie,
	 RTW89_HCIFC_POH},
	{RTW89_QTA_DBCC, hfc_chcfg_pcie_8852a,
	 &hfc_pubcfg_pcie_8852a, &hfc_preccfg_pcie,
	 RTW89_HCIFC_POH},
	{RTW89_QTA_SCC_WD128, hfc_chcfg_pcie_8852a,
	 &hfc_pubcfg_pcie_8852a, &hfc_preccfg_pcie_wd128,
	 RTW89_HCIFC_POH},
	{RTW89_QTA_DBCC_WD128, hfc_chcfg_pcie_8852a,
	 &hfc_pubcfg_pcie_8852a, &hfc_preccfg_pcie_wd128,
	 RTW89_HCIFC_POH},
	{RTW89_QTA_SCC_STF, hfc_chcfg_pcie_stf_8852a,
	 &hfc_pubcfg_pcie_stf_8852a, &hfc_preccfg_pcie_stf,
	 RTW89_HCIFC_STF},
	{RTW89_QTA_DBCC_STF, hfc_chcfg_pcie_stf_8852a,
	 &hfc_pubcfg_pcie_stf_8852a, &hfc_preccfg_pcie_stf,
	 RTW89_HCIFC_STF},
	{RTW89_QTA_SU_TP, hfc_chcfg_pcie_sutp_8852a,
	 &hfc_pubcfg_pcie_sutp_8852a, &hfc_preccfg_pcie,
	 RTW89_HCIFC_POH},
	{RTW89_QTA_DLFW, NULL, NULL, &hfc_preccfg_pcie, RTW89_HCIFC_POH},
	{RTW89_QTA_BCN_TEST, hfc_chcfg_pcie_bcn_test_8852a,
	 &hfc_pubcfg_pcie_bcn_test_8852a, &hfc_preccfg_pcie,
	 RTW89_HCIFC_POH},
	{0},
};

static struct rtw89_hfc_param_ini rtw8852a_hfc_param_ini_usb[] = {
	{RTW89_QTA_SCC, hfc_chcfg_usb_8852a_scc,
	 &hfc_pubcfg_usb_8852a_scc, &hfc_preccfg_usb,
	 RTW89_HCIFC_STF},
	{RTW89_QTA_DBCC, hfc_chcfg_usb_8852a_dbcc,
	 &hfc_pubcfg_usb_8852a_dbcc, &hfc_preccfg_usb,
	 RTW89_HCIFC_STF},
	{0},
};

static int hfc_reset_param(struct rtw89_dev *rtwdev)
{
	struct rtw89_hfc_param *param = hfc_get_param();
	struct rtw89_hfc_param_ini param_ini = {0};

	switch (rtwdev->hci.type) {
	case RTW89_HCI_TYPE_PCIE:
		param_ini = rtw8852a_hfc_param_ini_pcie[rtwdev->mac.dle_info.qta_mode];
		param->en = 0;
		if (param_ini.qta_mode != rtwdev->mac.dle_info.qta_mode)
			return -EINVAL;
		break;
	case RTW89_HCI_TYPE_USB:
		rtw89_info(rtwdev, "hfc param init usb, qta_mode:%d\n",
			   rtwdev->mac.dle_info.qta_mode);
		param_ini = rtw8852a_hfc_param_ini_usb[rtwdev->mac.dle_info.qta_mode];
		param->en = 0;
		if (param_ini.qta_mode != rtwdev->mac.dle_info.qta_mode) {
			rtw89_err(rtwdev, "failed qta_mode mismatch\n");
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	if (param_ini.pub_cfg)
		param->pub_cfg = param_ini.pub_cfg;

	if (param_ini.prec_cfg)
		param->prec_cfg = param_ini.prec_cfg;

	if (param_ini.ch_cfg)
		param->ch_cfg = param_ini.ch_cfg;

	memset(param->ch_info, 0, sizeof(*param->ch_info));
	memset(param->pub_info, 0, sizeof(*param->pub_info));
	param->mode = param_ini.mode;
	rtwdev->mac.hfc_param = param;

	return 0;
}

static int hfc_ch_cfg_chk(struct rtw89_dev *rtwdev, u8 ch)
{
	struct rtw89_hfc_param *param = rtwdev->mac.hfc_param;
	struct rtw89_hfc_ch_cfg *ch_cfg = param->ch_cfg;
	struct rtw89_hfc_pub_cfg *pub_cfg = param->pub_cfg;
	struct rtw89_hfc_prec_cfg *prec_cfg = param->prec_cfg;

	if (ch >= RTW89_DMA_CH_NUM)
		return -EINVAL;

	if ((ch_cfg[ch].min && ch_cfg[ch].min < prec_cfg->ch011_prec) ||
	    ch_cfg[ch].max > pub_cfg->pub_max)
		return -EINVAL;
	if (ch_cfg[ch].grp >= grp_num)
		return -EINVAL;

	return 0;
}

static int hfc_pub_info_chk(struct rtw89_dev *rtwdev)
{
	struct rtw89_hfc_param *param = rtwdev->mac.hfc_param;
	struct rtw89_hfc_pub_cfg *cfg = param->pub_cfg;
	struct rtw89_hfc_pub_info *info = param->pub_info;

	if (info->g0_used + info->g1_used + info->pub_aval != cfg->pub_max) {
		if (1)
//		if (is_chip_id(adapter, RTW89_CHIP_ID_8852A))
			return 0;
		else
			return -EFAULT;
	}

	return 0;
}

static int hfc_pub_cfg_chk(struct rtw89_dev *rtwdev)
{
	struct rtw89_hfc_param *param = rtwdev->mac.hfc_param;
	struct rtw89_hfc_pub_cfg *pub_cfg = param->pub_cfg;

	if (pub_cfg->grp0 + pub_cfg->grp1 != pub_cfg->pub_max)
		return 0; // TODO: return MACHFCPUBQTA? TBD

	return 0;
}

static int hfc_ch_ctrl(struct rtw89_dev *rtwdev, u8 ch)
{
	struct rtw89_hfc_param *param = rtwdev->mac.hfc_param;
	struct rtw89_hfc_ch_cfg *cfg = param->ch_cfg;
	int ret = 0;
	u32 val = 0;

	ret = rtw89_mac_check_mac_en(rtwdev, 0, RTW89_DMAC_SEL);
	if (ret)
		return ret;

	ret = hfc_ch_cfg_chk(rtwdev, ch);
	if (ret)
		return ret;

	if (ch > RTW89_DMA_B1HI)
		return -EINVAL;

	val = u32_encode_bits(cfg[ch].min, B_AX_MIN_PG_MASK) |
	      u32_encode_bits(cfg[ch].max, B_AX_MAX_PG_MASK) |
	      (cfg[ch].grp ? B_AX_GRP : 0);
	rtw89_write32(rtwdev, R_AX_ACH0_PAGE_CTRL + ch * 4, val);

	return 0;
}

static int hfc_upd_ch_info(struct rtw89_dev *rtwdev, u8 ch)
{
	struct rtw89_hfc_param *param = rtwdev->mac.hfc_param;
	struct rtw89_hfc_ch_info *info = param->ch_info;
	struct rtw89_hfc_ch_cfg *cfg = param->ch_cfg;
	u32 val;
	u32 ret;

	ret = rtw89_mac_check_mac_en(rtwdev, 0, RTW89_DMAC_SEL);
	if (ret)
		return ret;

	if (ch > RTW89_DMA_H2C)
		return -EINVAL;

	val = rtw89_read32(rtwdev, R_AX_ACH0_PAGE_INFO + ch * 4);
	info[ch].aval = u32_get_bits(val, B_AX_AVAL_PG_MASK);
	if (ch < RTW89_DMA_H2C)
		info[ch].used = u32_get_bits(val, B_AX_USE_PG_MASK);
	else
		info[ch].used = cfg[ch].min - info[ch].aval;

	return 0;
}

static int hfc_pub_ctrl(struct rtw89_dev *rtwdev)
{
	struct rtw89_hfc_pub_cfg *cfg = rtwdev->mac.hfc_param->pub_cfg;
	u32 val;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, 0, RTW89_DMAC_SEL);
	if (ret)
		return ret;

	ret = hfc_pub_cfg_chk(rtwdev);
	if (ret)
		return ret;

	val = u32_encode_bits(cfg->grp0, B_AX_PUBPG_G0_MASK) |
	      u32_encode_bits(cfg->grp1, B_AX_PUBPG_G1_MASK);
	rtw89_write32(rtwdev, R_AX_PUB_PAGE_CTRL1, val);

	val = u32_encode_bits(cfg->wp_thrd, B_AX_WP_THRD_MASK);
	rtw89_write32(rtwdev, R_AX_WP_PAGE_CTRL2, val);

	return 0;
}

static int hfc_upd_mix_info(struct rtw89_dev *rtwdev)
{
	struct rtw89_hfc_param *param = rtwdev->mac.hfc_param;
	struct rtw89_hfc_pub_cfg *pub_cfg = param->pub_cfg;
	struct rtw89_hfc_prec_cfg *prec_cfg = param->prec_cfg;
	struct rtw89_hfc_pub_info *info = param->pub_info;
	u32 val;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, 0, RTW89_DMAC_SEL);
	if (ret)
		return ret;

	val = rtw89_read32(rtwdev, R_AX_PUB_PAGE_INFO1);
	info->g0_used = u32_get_bits(val, B_AX_G0_USE_PG_MASK);
	info->g1_used = u32_get_bits(val, B_AX_G1_USE_PG_MASK);
	val = rtw89_read32(rtwdev, R_AX_PUB_PAGE_INFO3);
	info->g0_aval = u32_get_bits(val, B_AX_G0_AVAL_PG_MASK);
	info->g1_aval = u32_get_bits(val, B_AX_G1_AVAL_PG_MASK);
	info->pub_aval =
		u32_get_bits(rtw89_read32(rtwdev, R_AX_PUB_PAGE_INFO2),
			     B_AX_PUB_AVAL_PG_MASK);
	info->wp_aval =
		u32_get_bits(rtw89_read32(rtwdev, R_AX_WP_PAGE_INFO1),
			     B_AX_WP_AVAL_PG_MASK);

	val = rtw89_read32(rtwdev, R_AX_HCI_FC_CTRL);
	param->en = val & B_AX_HCI_FC_EN ? 1 : 0;
	param->h2c_en = val & B_AX_HCI_FC_CH12_EN ? 1 : 0;
	param->mode = u32_get_bits(val, B_AX_HCI_FC_MODE_MASK);
	prec_cfg->ch011_full_cond =
		u32_get_bits(val, B_AX_HCI_FC_WD_FULL_COND_MASK);
	prec_cfg->h2c_full_cond =
		u32_get_bits(val, B_AX_HCI_FC_CH12_FULL_COND_MASK);
	prec_cfg->wp_ch07_full_cond =
		u32_get_bits(val, B_AX_HCI_FC_WP_CH07_FULL_COND_MASK);
	prec_cfg->wp_ch811_full_cond =
		u32_get_bits(val, B_AX_HCI_FC_WP_CH811_FULL_COND_MASK);

	val = rtw89_read32(rtwdev, R_AX_CH_PAGE_CTRL);
	prec_cfg->ch011_prec = u32_get_bits(val, B_AX_PREC_PAGE_CH011_MASK);
	prec_cfg->h2c_prec = u32_get_bits(val, B_AX_PREC_PAGE_CH12_MASK);

	val = rtw89_read32(rtwdev, R_AX_PUB_PAGE_CTRL2);
	pub_cfg->pub_max = u32_get_bits(val, B_AX_PUBPG_ALL_MASK);

	val = rtw89_read32(rtwdev, R_AX_WP_PAGE_CTRL1);
	prec_cfg->wp_ch07_prec = u32_get_bits(val, B_AX_PREC_PAGE_WP_CH07_MASK);
	prec_cfg->wp_ch811_prec = u32_get_bits(val, B_AX_PREC_PAGE_WP_CH811_MASK);

	val = rtw89_read32(rtwdev, R_AX_WP_PAGE_CTRL2);
	pub_cfg->wp_thrd = u32_get_bits(val, B_AX_WP_THRD_MASK);

	val = rtw89_read32(rtwdev, R_AX_PUB_PAGE_CTRL1);
	pub_cfg->grp0 = u32_get_bits(val, B_AX_PUBPG_G0_MASK);
	pub_cfg->grp1 = u32_get_bits(val, B_AX_PUBPG_G1_MASK);

	ret = hfc_pub_info_chk(rtwdev);
	if (param->en && ret)
		return ret;

	return 0;
}

static void hfc_h2c_cfg(struct rtw89_dev *rtwdev)
{
	struct rtw89_hfc_param *param = rtwdev->mac.hfc_param;
	struct rtw89_hfc_prec_cfg *prec_cfg = param->prec_cfg;
	u32 val;

	val = u32_encode_bits(prec_cfg->h2c_prec, B_AX_PREC_PAGE_CH12_MASK);
	rtw89_write32(rtwdev, R_AX_CH_PAGE_CTRL, val);

	rtw89_write32_mask(rtwdev, R_AX_HCI_FC_CTRL,
			   B_AX_HCI_FC_CH12_FULL_COND_MASK,
			   prec_cfg->h2c_full_cond);
}

static void hfc_mix_cfg(struct rtw89_dev *rtwdev)
{
	struct rtw89_hfc_param *param = rtwdev->mac.hfc_param;
	struct rtw89_hfc_pub_cfg *pub_cfg = param->pub_cfg;
	struct rtw89_hfc_prec_cfg *prec_cfg = param->prec_cfg;
	u32 val;

	val = u32_encode_bits(prec_cfg->ch011_prec, B_AX_PREC_PAGE_CH011_MASK) |
	      u32_encode_bits(prec_cfg->h2c_prec, B_AX_PREC_PAGE_CH12_MASK);
	rtw89_write32(rtwdev, R_AX_CH_PAGE_CTRL, val);

	val = u32_encode_bits(pub_cfg->pub_max, B_AX_PUBPG_ALL_MASK);
	rtw89_write32(rtwdev, R_AX_PUB_PAGE_CTRL2, val);

	val = u32_encode_bits(prec_cfg->wp_ch07_prec,
			      B_AX_PREC_PAGE_WP_CH07_MASK) |
	      u32_encode_bits(prec_cfg->wp_ch811_prec,
			      B_AX_PREC_PAGE_WP_CH811_MASK);
	rtw89_write32(rtwdev, R_AX_WP_PAGE_CTRL1, val);

	val = u32_replace_bits(rtw89_read32(rtwdev, R_AX_HCI_FC_CTRL),
			       param->mode, B_AX_HCI_FC_MODE_MASK);
	val = u32_replace_bits(val, prec_cfg->ch011_full_cond,
			       B_AX_HCI_FC_WD_FULL_COND_MASK);
	val = u32_replace_bits(val, prec_cfg->h2c_full_cond,
			       B_AX_HCI_FC_CH12_FULL_COND_MASK);
	val = u32_replace_bits(val, prec_cfg->wp_ch07_full_cond,
			       B_AX_HCI_FC_WP_CH07_FULL_COND_MASK);
	val = u32_replace_bits(val, prec_cfg->wp_ch811_full_cond,
			       B_AX_HCI_FC_WP_CH811_FULL_COND_MASK);
	rtw89_write32(rtwdev, R_AX_HCI_FC_CTRL, val);
}

static void hfc_func_en(struct rtw89_dev *rtwdev, bool en, bool h2c_en)
{
	struct rtw89_hfc_param *param = rtwdev->mac.hfc_param;
	u32 val;

	val = rtw89_read32(rtwdev, R_AX_HCI_FC_CTRL);
	param->en = en;
	param->h2c_en = h2c_en;
	val = en ? (val | B_AX_HCI_FC_EN) : (val & ~B_AX_HCI_FC_EN);
	val = h2c_en ? (val | B_AX_HCI_FC_CH12_EN) :
			 (val & ~B_AX_HCI_FC_CH12_EN);
	rtw89_write32(rtwdev, R_AX_HCI_FC_CTRL, val);
}

static int hfc_init(struct rtw89_dev *rtwdev, bool reset, bool en, bool h2c_en)
{
	u8 ch;
	u32 ret = 0;

	if (reset)
		ret = hfc_reset_param(rtwdev);
	if (ret)
		return ret;

	ret = rtw89_mac_check_mac_en(rtwdev, 0, RTW89_DMAC_SEL);
	if (ret)
		return ret;

	hfc_func_en(rtwdev, false, false);

	if (!en && h2c_en) {
		hfc_h2c_cfg(rtwdev);
		return ret;
	}

	for (ch = RTW89_DMA_ACH0; ch < RTW89_DMA_H2C; ch++) {
		ret = hfc_ch_ctrl(rtwdev, ch);
		if (ret)
			return ret;
	}

	ret = hfc_pub_ctrl(rtwdev);
	if (ret)
		return ret;

	hfc_mix_cfg(rtwdev);
	if (en || h2c_en) {
		hfc_func_en(rtwdev, en, h2c_en);
		udelay(10);
	}
	for (ch = RTW89_DMA_ACH0; ch < RTW89_DMA_H2C; ch++) {
		ret = hfc_upd_ch_info(rtwdev, ch);
		if (ret)
			return ret;
	}
	ret = hfc_upd_mix_info(rtwdev);

	return ret;
}

#define PWR_POLL_CNT	2000
static int pwr_cmd_poll(struct rtw89_dev *rtwdev,
			struct rtw89_pwr_cfg *cfg)
{
	u8 val = 0;
	u32 addr;
	u32 cnt;

	cnt = PWR_POLL_CNT;
	addr = cfg->addr;

	if (cfg->base == PWR_INTF_MSK_SDIO)
		addr = cfg->addr | SDIO_LOCAL_BASE_ADDR;

	while (cnt--) {
		val = rtw89_read8(rtwdev, addr);
		val &= cfg->msk;
		if (val == (cfg->val & cfg->msk))
			return 0;
		mdelay(1);
	}

	rtw89_warn(rtwdev, "[ERR] Polling timeout\n");
	rtw89_warn(rtwdev, "[ERR] addr: %X, %X\n", addr, cfg->addr);
	rtw89_warn(rtwdev, "[ERR] val: %X, %X\n", val, cfg->val);

	return -EBUSY;
}

static int rtw89_mac_sub_pwr_seq(struct rtw89_dev *rtwdev, u8 cut_msk,
				 u8 intf_msk, struct rtw89_pwr_cfg *cfg)
{
	struct rtw89_pwr_cfg *cur_cfg;
	u32 addr;
	u8 val;

	for (cur_cfg = cfg; cur_cfg->cmd != PWR_CMD_END; cur_cfg++) {
		if (!(cur_cfg->intf_msk & intf_msk) ||
		    !(cur_cfg->cut_msk & cut_msk))
			continue;

		switch (cur_cfg->cmd) {
		case PWR_CMD_WRITE:
			addr = cur_cfg->addr;

			if (cur_cfg->base == PWR_BASE_SDIO)
				addr |= SDIO_LOCAL_BASE_ADDR;

			val = rtw89_read8(rtwdev, addr);
			val &= ~(cur_cfg->msk);
			val |= (cur_cfg->val & cur_cfg->msk);

			rtw89_write8(rtwdev, addr, val);
			break;
		case PWR_CMD_POLL:
			if (pwr_cmd_poll(rtwdev, cur_cfg))
				return -EBUSY;
			break;
		case PWR_CMD_DELAY:
			if (cur_cfg->val == PWR_DELAY_US)
				udelay(cur_cfg->addr);
			else
				mdelay(cur_cfg->addr);
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int rtw89_mac_pwr_seq(struct rtw89_dev *rtwdev,
			     struct rtw89_pwr_cfg **cfg_seq)
{
	//u8 cut_mask;
	//u8 intf_mask;
	u32 idx = 0;
	struct rtw89_pwr_cfg *cfg;
	int ret;

	do {
		cfg = cfg_seq[idx];
		if (!cfg)
			break;

		ret = rtw89_mac_sub_pwr_seq(rtwdev, BIT(0), BIT(2), cfg);
		if (ret)
			return -EBUSY;

		idx++;
	} while (1);

	return 0;
}

static struct rtw89_pwr_cfg rtw89_pwron_8852a[] = {
	{0x0005,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_WRITE, BIT(7), 0},
	{0x0005,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_WRITE, BIT(2), 0},
	{0x0006,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_POLL, BIT(1), BIT(1)},
	{0x0006,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0005,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0005,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_POLL, BIT(0), 0},
	{0x0088,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0083,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_WRITE, BIT(6), 0},
	{0x0080,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_WRITE, BIT(5), BIT(5)},
	{0x0024,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_WRITE, BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0), 0},
	{0x02A0,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_WRITE, BIT(1), BIT(1)},
	{0xFFFF,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 0,
	 PWR_CMD_END, 0, 0},
};

static struct rtw89_pwr_cfg rtw89_pwroff_8852a[] = {
	{0x0006,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0005,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_WRITE, BIT(1), BIT(1)},
	{0x0005,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 PWR_BASE_MAC,
	 PWR_CMD_POLL, BIT(1), 0},
	{0xFFFF,
	 PWR_CUT_MSK_ALL,
	 PWR_INTF_MSK_ALL,
	 0,
	 PWR_CMD_END, 0, 0},
};

struct rtw89_pwr_cfg *pwr_on_seq_8852a[] = {
	rtw89_pwron_8852a,
	NULL
};

struct rtw89_pwr_cfg *pwr_off_seq_8852a[] = {
	rtw89_pwroff_8852a,
	NULL
};

static int rtw89_mac_power_switch(struct rtw89_dev *rtwdev, bool on)
{
#define PWR_ACT 1
	struct rtw89_pwr_cfg **cfg_seq;
	int ret;
	u8 val;

	if (on)
		cfg_seq = pwr_on_seq_8852a;
	else
		cfg_seq = pwr_off_seq_8852a;

	val = rtw89_read8(rtwdev, 0x3F1) & 0x3;
	pr_info("%s: 0x3F1 val=%d\n", __func__, val);
	if (on && val == PWR_ACT) {
		rtw89_err(rtwdev, "MAC has already powered on\n");
		return -EBUSY;
	}

	ret = rtw89_mac_pwr_seq(rtwdev, cfg_seq);
	if (ret)
		return ret;

	return 0;
#undef PWR_ACT
}

int rtw89_mac_pwr_on(struct rtw89_dev *rtwdev)
{
	int ret;

	ret = rtw89_mac_power_switch(rtwdev, true);
	if (ret) {
		rtw89_warn(rtwdev, "power on fail\n");
		return ret;
	}

	return 0;
} 

void rtw89_mac_pwr_off(struct rtw89_dev *rtwdev)
{
	rtw89_mac_power_switch(rtwdev, false);
}

static int cmac_func_en(struct rtw89_dev *rtwdev, u8 band, bool en)
{
	u32 func_en = 0;
	u32 ck_en = 0;
	u32 c1pc_en = 0;
	u32 addrl_func_en[] = {R_AX_CMAC_FUNC_EN, R_AX_CMAC_FUNC_EN_C1};
	u32 addrl_ck_en[] = {R_AX_CK_EN, R_AX_CK_EN_C1};

	func_en = B_AX_CMAC_EN | B_AX_CMAC_TXEN | B_AX_CMAC_RXEN |
			B_AX_PHYINTF_EN | B_AX_CMAC_DMA_EN | B_AX_PTCLTOP_EN |
			B_AX_SCHEDULER_EN | B_AX_TMAC_EN | B_AX_RMAC_EN;
	ck_en = B_AX_CMAC_CKEN | B_AX_PHYINTF_CKEN | B_AX_CMAC_DMA_CKEN |
		      B_AX_PTCLTOP_CKEN | B_AX_SCHEDULER_CKEN | B_AX_TMAC_CKEN |
		      B_AX_RMAC_CKEN;
	c1pc_en = B_AX_R_SYM_WLCMAC1_PC_EN |
			B_AX_R_SYM_WLCMAC1_P1_PC_EN |
			B_AX_R_SYM_WLCMAC1_P2_PC_EN |
			B_AX_R_SYM_WLCMAC1_P3_PC_EN |
			B_AX_R_SYM_WLCMAC1_P4_PC_EN;

	if (en) {
		if (band == 1) {
			rtw89_write32_set(rtwdev, R_AX_AFE_CTRL1, c1pc_en);
			rtw89_write32_clr(rtwdev, R_AX_SYS_ISO_CTRL_EXTEND,
					  B_AX_R_SYM_ISO_CMAC12PP);
			rtw89_write32_set(rtwdev, R_AX_SYS_ISO_CTRL_EXTEND,
					  B_AX_CMAC1_FEN);
		}
		rtw89_write32_set(rtwdev, addrl_ck_en[band], ck_en);
		rtw89_write32_set(rtwdev, addrl_func_en[band], func_en);
	} else {
		rtw89_write32_clr(rtwdev, addrl_func_en[band], func_en);
		rtw89_write32_clr(rtwdev, addrl_ck_en[band], ck_en);
		if (band == 1) {
			rtw89_write32_clr(rtwdev, R_AX_SYS_ISO_CTRL_EXTEND,
					  B_AX_CMAC1_FEN);
			rtw89_write32_set(rtwdev, R_AX_SYS_ISO_CTRL_EXTEND,
					  B_AX_R_SYM_ISO_CMAC12PP);
			rtw89_write32_clr(rtwdev, R_AX_AFE_CTRL1, c1pc_en);
		}
	}

	return 0;
}

#define PCIE_POLL_BDRAM_RST_CNT 100
static int rst_bdram_pcie(struct rtw89_dev *rtwdev, u8 val)
{
	u32 cnt;

	rtw89_write32(rtwdev, R_AX_PCIE_INIT_CFG1,
		      rtw89_read32(rtwdev, R_AX_PCIE_INIT_CFG1) | B_AX_RST_BDRAM);

	cnt = PCIE_POLL_BDRAM_RST_CNT;
	while (cnt &&
	       rtw89_read32(rtwdev, R_AX_PCIE_INIT_CFG1) & B_AX_RST_BDRAM) {
		cnt--;
		udelay(1);
	}

	if (!cnt)
		return -EBUSY;

	return 0;
}

static void hci_func_en(struct rtw89_dev *rtwdev)
{
	u32 val32;

	val32 = (B_AX_HCI_TXDMA_EN | B_AX_HCI_RXDMA_EN);
	rtw89_write32_set(rtwdev, R_AX_HCI_FUNC_EN, val32);
}

static int dmac_func_en(struct rtw89_dev *rtwdev)
{
	u32 val32;
	u32 ret = 0;

	val32 = (B_AX_MAC_FUNC_EN | B_AX_DMAC_FUNC_EN | B_AX_MAC_SEC_EN |
		 B_AX_DISPATCHER_EN | B_AX_DLE_CPUIO_EN | B_AX_PKT_IN_EN |
		 B_AX_DMAC_TBL_EN | B_AX_PKT_BUF_EN | B_AX_STA_SCH_EN |
		 B_AX_TXPKT_CTRL_EN | B_AX_WD_RLS_EN | B_AX_MPDU_PROC_EN);
	rtw89_write32(rtwdev, R_AX_DMAC_FUNC_EN, val32);

	val32 = (B_AX_MAC_SEC_CLK_EN | B_AX_DISPATCHER_CLK_EN |
		 B_AX_DLE_CPUIO_CLK_EN | B_AX_PKT_IN_CLK_EN |
		 B_AX_STA_SCH_CLK_EN | B_AX_TXPKT_CTRL_CLK_EN |
		 B_AX_WD_RLS_CLK_EN);
	rtw89_write32(rtwdev, R_AX_DMAC_CLK_EN, val32);

	if (rtwdev->hci.type == RTW89_HCI_TYPE_PCIE) {
		ret = rst_bdram_pcie(rtwdev, 0);
		if (ret) {
			rtw89_err(rtwdev, "[ERR]dmac en rst pcie bdram %d\n", ret);
			return ret;
		}
	}

	return ret;
}

static int rtw89_mac_sys_init(struct rtw89_dev *rtwdev)
{
	int ret;

	ret = dmac_func_en(rtwdev);
	if (ret)
		return ret;

	ret = cmac_func_en(rtwdev, 0, true);
	if (ret)
		return ret;

	return ret;
}

/* PCIE 64 */
static struct rtw89_dle_size wde_size0 = {
	RTW89_WDE_PG_64,
	4032,
	64,
};

/* SDIO, PCIE STF, USB */
static struct rtw89_dle_size wde_size1 = {
	RTW89_WDE_PG_64,
	712,
	56,
};

/* PCIE 128 */
static struct rtw89_dle_size wde_size2 = {
	RTW89_WDE_PG_128,
	2016,
	32,
};

/* PCIE SU TP */
static struct rtw89_dle_size wde_size3 = {
	RTW89_WDE_PG_64,
	496,
	3600,
};

/* DLFW */
static struct rtw89_dle_size wde_size4 = {
	RTW89_WDE_PG_64,
	0,
	4096,
};

/* PCIE BCN TEST */
static struct rtw89_dle_size wde_size5 = {
	RTW89_WDE_PG_64,
	3904,
	64,
};

/* PCIE */
static struct rtw89_dle_size ple_size0 = {
	RTW89_PLE_PG_128,
	1536,
	0,
};

/* SDIO, USB */
static struct rtw89_dle_size ple_size1 = {
	RTW89_PLE_PG_128, /* pge_size */
	3200, /* lnk_pge_num */
	0, /* unlink_pge_num */
};

/* PCIE STF */
static struct rtw89_dle_size ple_size2 = {
	RTW89_PLE_PG_128,
	3200,
	0,
};

/* PCIE SU TP */
static struct rtw89_dle_size ple_size3 = {
	RTW89_PLE_PG_128,
	311,
	1225,
};

/* DLFW */
static struct rtw89_dle_size ple_size4 = {
	RTW89_PLE_PG_128,
	136,
	1400,
};

/* PCIE BCN TEST */
static struct rtw89_dle_size ple_size5 = {
	RTW89_PLE_PG_128,
	1520,
	80,
};

/* PCIE 64 */
static struct rtw89_wde_quota wde_qt0 = {
	3792,
	196,
	0,
	44,
};

/* SDIO, PCIE STF, USB */
static struct rtw89_wde_quota wde_qt1 = {
	512,
	196,
	2,
	2,
};

/* PCIE 128 */
static struct rtw89_wde_quota wde_qt2 = {
	1896,
	98,
	0,
	22,
};

/* PCIE SU TP */
static struct rtw89_wde_quota wde_qt3 = {
	256,
	196,
	0,
	44,
};

/* DLFW */
static struct rtw89_wde_quota wde_qt4 = {
	0,
	0,
	0,
	0,
};

/* PCIE BCN TEST */
static struct rtw89_wde_quota wde_qt5 = {
	3666,
	196,
	0,
	44,
};

/* LA-PCIE */
static struct rtw89_wde_quota wde_qt9 = {
	1392,
	8,
	0,
	8,
};

/* PCIE DBCC */
static struct rtw89_ple_quota ple_qt0 = {
	588,
	147,
	16,
	20,
	26,
	26,
	356,
	89,
	32,
	40,
	1,
};

/* PCIE DBCC */
static struct rtw89_ple_quota ple_qt1 = {
	783,
	342,
	211,
	20,
	64,
	221,
	551,
	284,
	64,
	128,
	1,
};

/* PCIE SCC */
static struct rtw89_ple_quota ple_qt4 = {
	588,
	0,
	16,
	20,
	26,
	26,
	356,
	0,
	32,
	40,
	1,
};

/* PCIE SCC */
static struct rtw89_ple_quota ple_qt5 = {
	1019,
	431,
	447,
	20,
	64,
	457,
	787,
	431,
	64,
	128,
	1,
};

/* PCIE STF SCC */
static struct rtw89_ple_quota ple_qt8 = {
	1536,
	0,
	16,
	20,
	13,
	26,
	356,
	0,
	32,
	40,
	1,
};

/* PCIE STF SCC */
static struct rtw89_ple_quota ple_qt9 = {
	2696,
	1160,
	1176,
	20,
	64,
	1186,
	1516,
	1160,
	64,
	128,
	1,
};

/* PCIE STF DBCC */
static struct rtw89_ple_quota ple_qt10 = {
	2272,
	0,
	16,
	20,
	26,
	26,
	356,
	89,
	32,
	40,
	1
};

/* PCIE STF DBCC */
static struct rtw89_ple_quota ple_qt11 = {
	2594,
	322,
	338,
	20,
	64,
	348,
	678,
	411,
	64,
	128,
	1
};

/* PCIE SU TP */
static struct rtw89_ple_quota ple_qt12 = {
	50,
	50,
	16,
	20,
	26,
	26,
	25,
	25,
	32,
	40,
	1
};

/* DLFW */
static struct rtw89_ple_quota ple_qt13 = {
	0,
	0,
	16,
	120,
	0,
	0,
	0,
	0,
	0,
	0,
	0
};

/* PCIE BCN TEST */
static struct rtw89_ple_quota ple_qt14 = {
	588,
	147,
	16,
	20,
	26,
	26,
	356,
	89,
	32,
	40,
	80,
};

/* PCIE BCN TEST */
static struct rtw89_ple_quota ple_qt15 = {
	688,
	247,
	116,
	20,
	64,
	126,
	456,
	189,
	64,
	128,
	80,
};

/* USB DBCC */
static struct rtw89_ple_quota ple_qt16 = {
	2048, /* cmac0_tx */
	0, /* cmac1_tx */
	16, /* c2h */
	48, /* h2c */
	26, /* wcpu */
	26, /* mpdu_proc */
	360, /* cmac0_dma */
	90, /* cma1_dma */
	32, /* bb_rpt */
	40, /* wd_rel */
	1, /* cpu_io */
};

/* USB DBCC */
static struct rtw89_ple_quota ple_qt17 = {
	2048, /* cmac0_tx */
	0, /* cmac1_tx */
	529, /* c2h */
	48, /* h2c */
	64, /* wcpu */
	539, /* mpdu_proc */
	873, /* cmac0_dma */
	603, /* cma1_dma */
	64, /* bb_rpt */
	128, /* wd_rel */
	1, /* cpu_io */
};

/* LA-PCIE MIN*/
static struct rtw89_ple_quota ple_qt23 = {
	156,
	39,
	16,
	20,
	26,
	26,
	356,
	89,
	32,
	40,
	1,
};

/* LA-PCIE MAX*/
static struct rtw89_ple_quota ple_qt24 = {
	187,
	70,
	47,
	20,
	64,
	57,
	387,
	120,
	64,
	128,
	1,
};

/* USB SCC */
static struct rtw89_ple_quota ple_qt25 = {
	1536, /* cmac0_tx */
	0, /* cmac1_tx */
	16, /* c2h */
	48, /* h2c */
	13, /* wcpu */
	26, /* mpdu_proc */
	360, /* cmac0_dma */
	0, /* cma1_dma */
	32, /* bb_rpt */
	40, /* wd_rel */
	1, /* cpu_io */
};

/* USB SCC */
static struct rtw89_ple_quota ple_qt26 = {
	1536, /* cmac0_tx */
	0, /* cmac1_tx */
	1144, /* c2h */
	48, /* h2c */
	64, /* wcpu */
	1154, /* mpdu_proc */
	1488, /* cmac0_dma */
	0, /* cma1_dma */
	64, /* bb_rpt */
	128, /* wd_rel */
	1, /* cpu_io */
};

static struct rtw89_dle_mem rtw8852a_dle_mem_pcie[] = {
	{RTW89_QTA_SCC,
	 &wde_size0, &ple_size0,
	 &wde_qt0, &wde_qt0,
	 &ple_qt4, &ple_qt5},
	{RTW89_QTA_DBCC,
	 &wde_size0, &ple_size0,
	 &wde_qt0, &wde_qt0,
	 &ple_qt0, &ple_qt1},
	{RTW89_QTA_SCC_WD128,
	 &wde_size2, &ple_size0,
	 &wde_qt2, &wde_qt2,
	 &ple_qt4, &ple_qt5},
	{RTW89_QTA_DBCC_WD128,
	 &wde_size2, &ple_size0,
	 &wde_qt2, &wde_qt2,
	 &ple_qt0, &ple_qt1},
	{RTW89_QTA_SCC_STF,
	 &wde_size1, &ple_size2,
	 &wde_qt1, &wde_qt1,
	 &ple_qt8, &ple_qt9},
	{RTW89_QTA_DBCC_STF,
	 &wde_size1, &ple_size2,
	 &wde_qt1, &wde_qt1,
	 &ple_qt10, &ple_qt11},
	{RTW89_QTA_SU_TP,
	 &wde_size3, &ple_size3,
	 &wde_qt3, &wde_qt3,
	 &ple_qt12, &ple_qt12},
	{RTW89_QTA_DLFW,
	 &wde_size4, &ple_size4,
	 &wde_qt4, &wde_qt4,
	 &ple_qt13, &ple_qt13},
	{RTW89_QTA_BCN_TEST,
	 &wde_size5, &ple_size5,
	 &wde_qt5, &wde_qt5,
	 &ple_qt14, &ple_qt15},
	{RTW89_QTA_LAMODE,
	 &wde_size5, &ple_size5,
	 &wde_qt9, &wde_qt9,
	 &ple_qt23, &ple_qt24},
	{RTW89_QTA_INVALID, NULL, NULL, NULL, NULL, NULL, NULL},
};

static struct rtw89_dle_mem rtw8852a_dle_mem_usb[] = {
	{RTW89_QTA_SCC, /* qta_mode */
	 &wde_size1, &ple_size1, /* wde_size, ple_size */
	 &wde_qt1, &wde_qt1, /* wde_min_qt, wde_max_qt */
	 &ple_qt25, &ple_qt26}, /* ple_min_qt, ple_max_qt */
	{RTW89_QTA_DBCC, /* qta_mode */
	 &wde_size1, &ple_size1, /* wde_size, ple_size */
	 &wde_qt1, &wde_qt1, /* wde_min_qt, wde_max_qt */
	 &ple_qt16, &ple_qt17}, /* ple_min_qt, ple_max_qt */
	{RTW89_QTA_DLFW, /* qta_mode */
	 &wde_size4, &ple_size4, /* wde_size, ple_size */
	 &wde_qt4, &wde_qt4, /* wde_min_qt, wde_max_qt */
	 &ple_qt13, &ple_qt13}, /* ple_min_qt, ple_max_qt */
	{RTW89_QTA_INVALID, NULL, NULL, NULL, NULL, NULL, NULL},
};

static struct rtw89_dle_mem *get_dle_mem_cfg(struct rtw89_dev *rtwdev,
					     enum rtw89_qta_mode mode)
{
	struct rtw89_mac_info *mac = &rtwdev->mac;
	struct rtw89_dle_mem *cfg = NULL;

	if (rtwdev->hci.type == RTW89_HCI_TYPE_PCIE)
		cfg = &rtw8852a_dle_mem_pcie[mode];
	else if (rtwdev->hci.type == RTW89_HCI_TYPE_USB) {
		rtw89_info(rtwdev, "get_dle_mem_cfg: rtw8852a_dle_mem_usb\n");
		cfg = &rtw8852a_dle_mem_usb[mode];
	}

	if (!cfg) {
		rtw89_err(rtwdev, "failed to get dle mem cfg\n");
		return NULL;
	}

	for (; cfg->mode != RTW89_QTA_INVALID; cfg++) {
		if (cfg->mode == mode) {
			mac->dle_info.wde_pg_size = cfg->wde_size->pge_size;
			mac->dle_info.ple_pg_size = cfg->ple_size->pge_size;
			mac->dle_info.qta_mode = mode;
			return cfg;
		}
	}

	return NULL;
}

static inline u32 dle_used_size(struct rtw89_dle_size *wde,
				struct rtw89_dle_size *ple)
{
	return wde->pge_size * (wde->lnk_pge_num + wde->unlnk_pge_num) +
	       ple->pge_size * (ple->lnk_pge_num + ple->unlnk_pge_num);
}

static void dle_func_en(struct rtw89_dev *rtwdev, bool enable)
{
	u32 val;

	/* TODO: use register set clear */
	val = rtw89_read32(rtwdev, R_AX_DMAC_FUNC_EN);
	if (enable)
		val |= (B_AX_DLE_WDE_EN | B_AX_DLE_PLE_EN);
	else
		val &= ~(B_AX_DLE_WDE_EN | B_AX_DLE_PLE_EN);
	rtw89_write32(rtwdev, R_AX_DMAC_FUNC_EN, val);
}

static void dle_clk_en(struct rtw89_dev *rtwdev, bool enable)
{
	u32 val;

	/* TODO: use register set clear */
	val = rtw89_read32(rtwdev, R_AX_DMAC_CLK_EN);
	if (enable)
		val |= (B_AX_DLE_WDE_CLK_EN | B_AX_DLE_PLE_CLK_EN);
	else
		val &= ~(B_AX_DLE_WDE_CLK_EN | B_AX_DLE_PLE_CLK_EN);
	rtw89_write32(rtwdev, R_AX_DMAC_CLK_EN, val);
}

static void dle_mix_cfg(struct rtw89_dev *rtwdev, struct rtw89_dle_mem *cfg)
{
	struct rtw89_dle_size *size_cfg;
	u32 val;
	u8 bound = 0;

	val = rtw89_read32(rtwdev, R_AX_WDE_PKTBUF_CFG);
	size_cfg = cfg->wde_size;

	switch (size_cfg->pge_size) {
	default:
	case RTW89_WDE_PG_64:
		val = u32_replace_bits(val, S_AX_WDE_PAGE_SEL_64,
				       B_AX_WDE_PAGE_SEL_MASK);
		rtw89_write32_set(rtwdev, R_AX_DISPATCHER_GLOBAL_SETTING_0,
				  B_AX_WD_PAGE_64B_SEL);
		break;
	case RTW89_WDE_PG_128:
		val = u32_replace_bits(val, S_AX_WDE_PAGE_SEL_128,
				       B_AX_WDE_PAGE_SEL_MASK);
		rtw89_write32_clr(rtwdev, R_AX_DISPATCHER_GLOBAL_SETTING_0,
				  B_AX_WD_PAGE_64B_SEL);
		break;
	case RTW89_WDE_PG_256:
		val = u32_replace_bits(val, S_AX_WDE_PAGE_SEL_256,
				       B_AX_WDE_PAGE_SEL_MASK);
		rtw89_err(rtwdev, "[ERR]WDE DLE doesn't support 256 byte!\n");
		break;
	}

	val = u32_replace_bits(val, bound, B_AX_WDE_START_BOUND_MASK);
	val = u32_replace_bits(val, size_cfg->lnk_pge_num,
			       B_AX_WDE_FREE_PAGE_NUM_MASK);
	rtw89_write32(rtwdev, R_AX_WDE_PKTBUF_CFG, val);

	val = rtw89_read32(rtwdev, R_AX_PLE_PKTBUF_CFG);
	bound = (size_cfg->lnk_pge_num + size_cfg->unlnk_pge_num)
				* size_cfg->pge_size / DLE_BOUND_UNIT;
	size_cfg = cfg->ple_size;

	switch (size_cfg->pge_size) {
	default:
	case RTW89_PLE_PG_64:
		val = u32_replace_bits(val, S_AX_PLE_PAGE_SEL_64,
				       B_AX_PLE_PAGE_SEL_MASK);
		rtw89_err(rtwdev, "[ERR]PLE DLE doesn't support 64 byte!\n");
		break;
	case RTW89_PLE_PG_128:
		val = u32_replace_bits(val, S_AX_PLE_PAGE_SEL_128,
				       B_AX_PLE_PAGE_SEL_MASK);
		rtw89_write32_set(rtwdev, R_AX_DISPATCHER_GLOBAL_SETTING_0,
				  B_AX_PL_PAGE_128B_SEL);
		break;
	case RTW89_PLE_PG_256:
		val = u32_replace_bits(val, S_AX_PLE_PAGE_SEL_256,
				       B_AX_PLE_PAGE_SEL_MASK);
		rtw89_write32_clr(rtwdev, R_AX_DISPATCHER_GLOBAL_SETTING_0,
				  B_AX_PL_PAGE_128B_SEL);
		break;
	}

	val = u32_replace_bits(val, bound, B_AX_PLE_START_BOUND_MASK);
	val = u32_replace_bits(val, size_cfg->lnk_pge_num,
			       B_AX_PLE_FREE_PAGE_NUM_MASK);
	rtw89_write32(rtwdev, R_AX_PLE_PKTBUF_CFG, val);
}

#define SET_QUOTA(_x, _module, _idx)					\
	do {								\
	val = (min_cfg->_x & B_AX_ ## _module ## _MIN_SIZE_MASK) |	\
	      ((max_cfg->_x << 16)& B_AX_ ## _module ## _MAX_SIZE_MASK);	\
	rtw89_write32(rtwdev, R_AX_ ## _module ## _QTA ## _idx ## _CFG, val);\
	} while(0)
static void wde_quota_cfg(struct rtw89_dev *rtwdev,
			  struct rtw89_wde_quota *min_cfg,
			  struct rtw89_wde_quota *max_cfg)
{
	u32 val;

	SET_QUOTA(hif, WDE, 0);
	SET_QUOTA(wcpu, WDE, 1);
	SET_QUOTA(pkt_in, WDE, 3);
	SET_QUOTA(cpu_io, WDE, 4);
}

static void ple_quota_cfg(struct rtw89_dev *rtwdev,
		   struct rtw89_ple_quota *min_cfg,
		   struct rtw89_ple_quota *max_cfg)
{
	u32 val;

	SET_QUOTA(cma0_tx, PLE, 0);
	SET_QUOTA(cma1_tx, PLE, 1);
	SET_QUOTA(c2h, PLE, 2);
	SET_QUOTA(h2c, PLE, 3);
	SET_QUOTA(wcpu, PLE, 4);
	SET_QUOTA(mpdu_proc, PLE, 5);
	SET_QUOTA(cma0_dma, PLE, 6);
	SET_QUOTA(cma1_dma, PLE, 7);
	SET_QUOTA(bb_rpt, PLE, 8);
	SET_QUOTA(wd_rel, PLE, 9);
	SET_QUOTA(cpu_io, PLE, 10);
}
#undef SET_QUOTA

static void dle_quota_cfg(struct rtw89_dev *rtwdev, struct rtw89_dle_mem *cfg)
{
	wde_quota_cfg(rtwdev, cfg->wde_min_qt, cfg->wde_max_qt);
	ple_quota_cfg(rtwdev, cfg->ple_min_qt, cfg->ple_max_qt);
}

int rtw89_mac_dle_init(struct rtw89_dev *rtwdev, enum rtw89_qta_mode mode,
		       enum rtw89_qta_mode ext_mode)
{
	struct rtw89_dle_mem *cfg, *ext_cfg;
	int ret = 0;
	u32 cnt;

	ret = rtw89_mac_check_mac_en(rtwdev, 0, RTW89_DMAC_SEL);
	if (ret)
		return ret;

	cfg = get_dle_mem_cfg(rtwdev, mode);
	if (!cfg) {
		rtw89_err(rtwdev, "[ERR]get_dle_mem_cfg\n");
		ret = -EINVAL;
		goto error;
	}

	if (mode == RTW89_QTA_DLFW) {
		ext_cfg = get_dle_mem_cfg(rtwdev, ext_mode);
		if (!ext_cfg) {
			rtw89_err(rtwdev, "[ERR]get_dle_mem_cfg ext\n");
			ret = -EINVAL;
			goto error;
		}
		cfg->wde_min_qt->wcpu = ext_cfg->wde_min_qt->wcpu;
	}

	if (dle_used_size(cfg->wde_size, cfg->ple_size) !=
			  rtwdev->chip->fifo_size) {
		rtw89_err(rtwdev, "[ERR]wd/dle mem cfg\n");
		ret = -EINVAL;
		goto error;
	}

	dle_func_en(rtwdev, false);
	dle_clk_en(rtwdev, true);

	dle_mix_cfg(rtwdev, cfg);
	dle_quota_cfg(rtwdev, cfg);

	dle_func_en(rtwdev, true);

	cnt = DLE_WAIT_CNT;
	while (cnt--) {
		if ((rtw89_read32(rtwdev, R_AX_WDE_INI_STATUS) & WDE_MGN_INI_RDY)
		    == WDE_MGN_INI_RDY)
			break;
	}

	if (!++cnt) {
		rtw89_err(rtwdev, "[ERR]WDE cfg ready\n");
		return -EBUSY;
	}

	cnt = DLE_WAIT_CNT;
	while (cnt--) {
		if ((rtw89_read32(rtwdev, R_AX_PLE_INI_STATUS) & PLE_MGN_INI_RDY)
		    == PLE_MGN_INI_RDY)
			break;
		udelay(1);
	}

	if (!++cnt) {
		rtw89_err(rtwdev, "[ERR]PLE cfg ready\n");
		return -EBUSY;
	}

	return 0;
error:
	dle_func_en(rtwdev, false);
	rtw89_err(rtwdev, "[ERR]trxcfg wde 0x8900 = %x\n",
		      rtw89_read32(rtwdev, R_AX_WDE_INI_STATUS));
	rtw89_err(rtwdev, "[ERR]trxcfg ple 0x8D00 = %x\n",
		      rtw89_read32(rtwdev, R_AX_PLE_INI_STATUS));

	return ret;
}

static int sta_sch_init(struct rtw89_dev *rtwdev)
{
	u32 cnt;
	u8 val;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, 0, RTW89_DMAC_SEL);
	if (ret)
		return ret;

	val = rtw89_read8(rtwdev, R_AX_SS_CTRL);
	val |= B_AX_SS_EN;
	rtw89_write8(rtwdev, R_AX_SS_CTRL, val);

	cnt = TRXCFG_WAIT_CNT;
	while (cnt--) {
		if (rtw89_read32(rtwdev, R_AX_SS_CTRL) & B_AX_SS_INIT_DONE_1)
			break;
		udelay(1);
	}

	if (!++cnt) {
		rtw89_err(rtwdev, "[ERR]STA scheduler init\n");
		return -EBUSY;
	}

	rtw89_write32_set(rtwdev, R_AX_SS_CTRL, B_AX_SS_WARM_INIT_FLG);

	return 0;
}

static int mpdu_proc_init(struct rtw89_dev *rtwdev)
{
	u32 val;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, 0, RTW89_DMAC_SEL);
	if (ret)
		return ret;

	rtw89_write32(rtwdev, R_AX_ACTION_FWD0, TRXCFG_MPDU_PROC_ACT_FRWD);
	rtw89_write32(rtwdev, R_AX_TF_FWD, TRXCFG_MPDU_PROC_TF_FRWD);
	val = rtw89_read32(rtwdev, R_AX_MPDU_PROC);
	val |= (B_AX_APPEND_FCS | B_AX_A_ICV_ERR);
	rtw89_write32(rtwdev, R_AX_MPDU_PROC, val);
	rtw89_write32(rtwdev, R_AX_CUT_AMSDU_CTRL, TRXCFG_MPDU_PROC_CUT_CTRL);

	return 0;
}

static int sec_eng_init(struct rtw89_dev *rtwdev)
{
	u32 val = 0;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, 0, RTW89_DMAC_SEL);
	if (ret)
		return ret;

	val = rtw89_read32(rtwdev, R_AX_SEC_ENG_CTRL);
	// init clock
	val |= (B_AX_CLK_EN_CGCMP | B_AX_CLK_EN_WAPI | B_AX_CLK_EN_WEP_TKIP);
	// init TX encryption
	val |= (B_AX_SEC_TX_ENC | B_AX_SEC_RX_DEC);
	val |= (B_AX_MC_DEC | B_AX_BC_DEC);
	val |= (B_AX_BMC_MGNT_DEC | B_AX_UC_MGNT_DEC);
	rtw89_write32(rtwdev, R_AX_SEC_ENG_CTRL, val);

	//init MIC ICV append
	val = rtw89_read32(rtwdev, R_AX_SEC_MPDU_PROC);
	val |= (B_AX_APPEND_ICV | B_AX_APPEND_MIC);

	// option init
	rtw89_write32(rtwdev, R_AX_SEC_MPDU_PROC, val);

	return 0;
}

static int dmac_init(struct rtw89_dev *rtwdev, u8 band)
{
	int ret;

#if 0
	pr_info("%s: dle_init\n", __func__);
	ret = dle_init(rtwdev, rtwdev->mac.dle_info.qta_mode);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]DLE init %d\n", ret);
		return ret;
	}
#endif

	pr_info("%s: hfc_init\n", __func__);
	ret = hfc_init(rtwdev, true, true, true);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]HCI FC init %d\n", ret);
		return ret;
	}

	pr_info("%s: sta_sch_init\n", __func__);
	ret = sta_sch_init(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]STA SCH init %d\n", ret);
		return ret;
	}

	pr_info("%s: mpdu_proc_init\n", __func__);
	ret = mpdu_proc_init(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]MPDU Proc init %d\n", ret);
		return ret;
	}

	pr_info("%s: sec_eng_init\n", __func__);
	ret = sec_eng_init(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]Security Engine init %d\n", ret);
		return ret;
	}

	pr_info("%s: <===\n", __func__);
	return ret;
}

static int addr_cam_init(struct rtw89_dev *rtwdev, u8 band)
{
	u32 val, cnt, reg;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, band, RTW89_CMAC_SEL);
	if (ret)
		return ret;

	reg = rtw89_mac_reg_by_band(R_AX_ADDR_CAM_CTRL, band);

	val = rtw89_read32(rtwdev, reg);
	val |= u32_encode_bits(0x7f, B_AX_ADDR_CAM_RANGE_MASK) |
	       B_AX_ADDR_CAM_CLR | B_AX_ADDR_CAM_EN;
	rtw89_write32(rtwdev, reg, val);

	cnt = TRXCFG_WAIT_CNT;
	while (cnt--) {
		if (!(rtw89_read16(rtwdev, reg) & B_AX_ADDR_CAM_CLR))
			break;
		udelay(1);
	}
	if (!++cnt) {
		rtw89_err(rtwdev, "[ERR]ADDR_CAM reset\n");
		return -EBUSY;
	}

	return 0;
}

static int scheduler_init(struct rtw89_dev *rtwdev, u8 band)
{
	//u32 val, reg;
	u32 ret;

	ret = rtw89_mac_check_mac_en(rtwdev, band, RTW89_CMAC_SEL);
	if (ret)
		return ret;

	return 0;
}

static int rtw89_mac_typ_fltr_opt(struct rtw89_dev *rtwdev,
				  enum rtw89_machdr_frame_type type,
				  enum rtw89_mac_fwd_target fwd_target,
				  u8 band)
{
	u32 val;

	switch (fwd_target) {
	case RTW89_FWD_DONT_CARE:
		val = RX_FLTR_FRAME_DROP;
		break;
	case RTW89_FWD_TO_HOST:
		val = RX_FLTR_FRAME_TO_HOST;
		break;
	case RTW89_FWD_TO_WLAN_CPU:
		val = RX_FLTR_FRAME_TO_WLCPU;
		break;
	default:
		rtw89_err(rtwdev, "[ERR]set rx filter fwd target err\n");
		return -EINVAL;
	}

	switch (type) {
	case RTW89_MGNT:
		rtw89_write32(rtwdev, rtw89_mac_reg_by_band(R_AX_MGNT_FLTR, band), val);
		break;
	case RTW89_CTRL:
		rtw89_write32(rtwdev, rtw89_mac_reg_by_band(R_AX_CTRL_FLTR, band), val);
		break;
	case RTW89_DATA:
		rtw89_write32(rtwdev, rtw89_mac_reg_by_band(R_AX_DATA_FLTR, band), val);
		break;
	default:
		rtw89_err(rtwdev, "[ERR]set rx filter type err\n");
		return -EINVAL;
	}

	return 0;
}

static int rx_fltr_init(struct rtw89_dev *rtwdev, u8 band)
{
	int ret, i;
	u32 mac_ftlr, plcp_ftlr;

	ret = rtw89_mac_check_mac_en(rtwdev, band, RTW89_CMAC_SEL);
	if (ret)
		return ret;

	for (i = RTW89_MGNT; i <= RTW89_DATA; i++) {
		ret = rtw89_mac_typ_fltr_opt(rtwdev, i, RTW89_FWD_TO_HOST,
					     band);
		if (ret)
			return ret;
	}
	mac_ftlr = B_AX_SNIFFER_MODE | B_AX_A_A1_MATCH | B_AX_A_BC |
		   B_AX_A_MC | B_AX_A_UC_CAM_MATCH | B_AX_A_BC_CAM_MATCH |
		   u32_encode_bits(3, B_AX_UID_FILTER_MASK);
	plcp_ftlr = B_AX_CCK_CRC_CHK | B_AX_SIGA_CRC_CHK |
		    B_AX_VHT_SU_SIGB_CRC_CHK | B_AX_VHT_MU_SIGB_CRC_CHK |
		    B_AX_HE_SIGB_CRC_CHK;
	rtw89_write32(rtwdev, rtw89_mac_reg_by_band(R_AX_RX_FLTR_OPT, band), mac_ftlr);
	rtw89_write32(rtwdev, rtw89_mac_reg_by_band(R_AX_PLCP_HDR_FLTR, band), plcp_ftlr);

	return 0;
}

static int cca_ctrl_init(struct rtw89_dev *rtwdev, u8 band)
{
	u32 val, reg;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, band, RTW89_CMAC_SEL);
	if (ret)
		return ret;

	reg = rtw89_mac_reg_by_band(R_AX_CCA_CONTROL, band);
	val = rtw89_read32(rtwdev, reg);
	val |= (B_AX_TB_CHK_TX_NAV | B_AX_TB_CHK_BASIC_NAV |
			B_AX_TB_CHK_BTCCA | B_AX_TB_CHK_EDCCA |
			B_AX_TB_CHK_CCA_S80 | B_AX_TB_CHK_CCA_S40 |
			B_AX_TB_CHK_CCA_S20 | B_AX_TB_CHK_CCA_P20 |
			B_AX_SIFS_CHK_BTCCA | B_AX_SIFS_CHK_EDCCA |
			B_AX_SIFS_CHK_CCA_S80 | B_AX_SIFS_CHK_CCA_S40 |
			B_AX_SIFS_CHK_CCA_S20 | B_AX_SIFS_CHK_CCA_P20 |
			B_AX_CTN_CHK_TXNAV | B_AX_CTN_CHK_INTRA_NAV |
			B_AX_CTN_CHK_BASIC_NAV | B_AX_CTN_CHK_BTCCA |
			B_AX_CTN_CHK_EDCCA | B_AX_CTN_CHK_CCA_S80 |
			B_AX_CTN_CHK_CCA_S40 | B_AX_CTN_CHK_CCA_S20 |
			B_AX_CTN_CHK_CCA_P20);
	rtw89_write32(rtwdev, reg, val);

	reg = rtw89_mac_reg_by_band(R_AX_RSP_CHK_SIG, band);
	val = rtw89_read32(rtwdev, reg);
	val |= (B_AX_RSP_CHK_TX_NAV | B_AX_RSP_CHK_INTRA_NAV |
			B_AX_RSP_CHK_BASIC_NAV | B_AX_RSP_CHK_SEC_CCA_80 |
			B_AX_RSP_CHK_SEC_CCA_40 | B_AX_RSP_CHK_SEC_CCA_20 |
			B_AX_RSP_CHK_BTCCA | B_AX_RSP_CHK_EDCCA |
			B_AX_RSP_CHK_CCA);
	rtw89_write32(rtwdev, reg, val);

	return 0;
}

static int spatial_reuse_init(struct rtw89_dev *rtwdev, u8 band)
{
	u32 reg;
	u8 val;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, band, RTW89_CMAC_SEL);
	if (ret)
		return ret;
	reg = rtw89_mac_reg_by_band(R_AX_RX_SR_CTRL, band);
	val = rtw89_read8(rtwdev, reg);
	val &= ~B_AX_SR_EN;
	rtw89_write8(rtwdev, reg, val);

	return 0;
}

static int tmac_init(struct rtw89_dev *rtwdev, u8 band)
{
	u32 val, reg;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, band, RTW89_CMAC_SEL);
	if (ret)
		return ret;
//TODO: ignore loopback mode?
	reg = rtw89_mac_reg_by_band(R_AX_MAC_LOOPBACK, band);
	val = rtw89_read32(rtwdev, reg);
	val &= ~B_AX_MACLBK_EN;
	rtw89_write32(rtwdev, reg, val);

	return 0;
}

static int rmac_init(struct rtw89_dev *rtwdev, u8 band)
{
#define TRXCFG_RMAC_CCA_TO	32
#define TRXCFG_RMAC_DATA_TO	15
	int ret;
	u32 reg;
	//u16 val;

	ret = rtw89_mac_check_mac_en(rtwdev, band, RTW89_CMAC_SEL);
	if (ret)
		return ret;

	reg = rtw89_mac_reg_by_band(R_AX_RESPBA_CAM_CTRL, band);
	rtw89_write8_set(rtwdev, reg, B_AX_SSN_SEL);
#if 0
	reg = rtw89_mac_reg_by_band(R_AX_DLK_PROTECT_CTL, band);
	val = rtw89_read16(rtwdev, reg);
	val = u16_replace_bits(val, TRXCFG_RMAC_DATA_TO,
			       B_AX_RX_DLK_DATA_TIME_MASK);
	val = u16_replace_bits(val, TRXCFG_RMAC_CCA_TO,
			       B_AX_RX_DLK_CCA_TIME_MASK);
	rtw89_write16(rtwdev, R_AX_DLK_PROTECT_CTL_C1, val);
#endif
	return ret;
}

static int cmac_com_init(struct rtw89_dev *rtwdev, u8 band)
{
	u32 val, reg;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, band, RTW89_CMAC_SEL);
	if (ret)
		return ret;

	reg = rtw89_mac_reg_by_band(R_AX_TX_SUB_CARRIER_VALUE, band);
	val = rtw89_read32(rtwdev, reg);
// loopback mode = 4
	if (1) {
		val = u32_replace_bits(val, 0, B_AX_TXSC_20M_MASK);
		val = u32_replace_bits(val, 0, B_AX_TXSC_40M_MASK);
		val = u32_replace_bits(val, 0, B_AX_TXSC_80M_MASK);
	} else {
		val = u32_replace_bits(val, 4, B_AX_TXSC_20M_MASK);
		val = u32_replace_bits(val, 4, B_AX_TXSC_40M_MASK);
		val = u32_replace_bits(val, 4, B_AX_TXSC_80M_MASK);
	}
	rtw89_write32(rtwdev, reg, val);

	return 0;
}

static int cmac_init(struct rtw89_dev *rtwdev, u8 band)
{
	int ret;

	ret = scheduler_init(rtwdev, band);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC%d SCH init %d\n", band, ret);
		return ret;
	}

	ret = addr_cam_init(rtwdev, band);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC%d ADDR_CAM reset %d\n", band, ret);
		return ret;
	}

	ret = rx_fltr_init(rtwdev, band);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC%d RX filter init %d\n", band, ret);
		return ret;
	}

	ret = cca_ctrl_init(rtwdev, band);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC%d CCA CTRL init %d\n", band, ret);
		return ret;
	}

	ret = spatial_reuse_init(rtwdev, band);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC%d Spatial Reuse init %d\n",
			  band, ret);
		return ret;
	}

	ret = tmac_init(rtwdev, band);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC%d TMAC init %d\n", band, ret);
		return ret;
	}

	ret = rmac_init(rtwdev, band);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC%d RMAC init %d\n", band, ret);
		return ret;
	}

	ret = cmac_com_init(rtwdev, band);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC%d Com init %d\n", band, ret);
		return ret;
	}

	return ret;
}

static int set_hw_sch_tx_en(struct rtw89_dev *rtwdev, u8 band, u16 tx_en,
			    u16 tx_en_mask)
{
	u32 reg = rtw89_mac_reg_by_band(R_AX_CTN_TXEN, band);
	u16 val;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, band, RTW89_CMAC_SEL);
	if (ret)
		return ret;

	val = rtw89_read16(rtwdev, reg);
	val = (val & ~tx_en_mask) | (tx_en & tx_en_mask);
	rtw89_write16(rtwdev, reg, val);

	return 0;
}

static int stop_sch_tx(struct rtw89_dev *rtwdev, u8 band,
		       u16 *tx_en, u16 *tx_en_mask)
{
	int ret;

	*tx_en =  rtw89_read16(rtwdev, rtw89_mac_reg_by_band(R_AX_CTN_TXEN, band));

	ret = set_hw_sch_tx_en(rtwdev, band, 0, 0xffff);
	if (ret)
		return ret;

	return 0;
}

static int resume_sch_tx(struct rtw89_dev *rtwdev, u8 band, u16 tx_en,
			 u16 tx_en_mask)
{
	int ret;

	ret = set_hw_sch_tx_en(rtwdev, band, tx_en, 0xffff);
	if (ret)
		return ret;

	return 0;
}

static int tx_idle_ck(struct rtw89_dev *rtwdev, u8 band)
{
	u32 cnt, addr, i;
	u8 val;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, band, RTW89_CMAC_SEL);
	if (ret)
		return ret;

	addr = rtw89_mac_reg_by_band(R_AX_PTCL_TX_CTN_SEL, band);

	cnt = PTCL_IDLE_POLL_CNT;
	while (--cnt) {
		val = rtw89_read8(rtwdev, addr);
		if (val & B_AX_PTCL_TX_ON_STAT) {
			udelay(SW_CVR_DUR_US);
		} else {
			for (i = 0; i < SW_CVR_CNT; i++) {
				val = rtw89_read8(rtwdev, addr);
				if (val & B_AX_PTCL_TX_ON_STAT)
					break;
				udelay(SW_CVR_DUR_US);
			}
			if (i >= SW_CVR_CNT)
				break;
		}
	}
	if (!cnt)
		return -EBUSY;

	return 0;
}

static u16 rtw89_mac_dle_buf_req(struct rtw89_dev *rtwdev, u16 buf_len,
				 bool wd)
{
	u32 val, timeout, reg;

	reg = wd ? R_AX_WD_BUF_REQ : R_AX_PL_BUF_REQ;
	val = buf_len;
	val |= B_AX_BUF_REQ_EXEC;
	rtw89_write32(rtwdev, reg, val);

	reg = wd ? R_AX_WD_BUF_STATUS : R_AX_PL_BUF_STATUS;
	timeout = 2000;
	while (timeout--) {
		val = rtw89_read32(rtwdev, reg);
		if (val & B_AX_BUF_STAT_DONE)
			break;
		udelay(1);
	}

	if (!++timeout)
		return 0xffff;

	return FIELD_GET(B_AX_BUF_STAT_PKTID_MASK, val);
}

static int rtw89_mac_set_cpuio(struct rtw89_dev *rtwdev,
			       struct rtw89_cpuio_ctrl *ctrl_para,
			       bool wd)
{
	u32 val, cmd_type, timeout, reg;

	cmd_type = ctrl_para->cmd_type;

	reg = wd ? R_AX_WD_CPUQ_OP_2 : R_AX_PL_CPUQ_OP_2;
	val = 0;
	val = u32_replace_bits(val, ctrl_para->start_pktid,
			       B_AX_CPUQ_OP_STRT_PKTID_MASK);
	val = u32_replace_bits(val, ctrl_para->end_pktid,
			       B_AX_CPUQ_OP_END_PKTID_MASK);
	rtw89_write32(rtwdev, reg, val);

	reg = wd ? R_AX_WD_CPUQ_OP_1 : R_AX_PL_CPUQ_OP_1;
	val = 0;
	val = u32_replace_bits(val, ctrl_para->src_pid,
			       B_AX_CPUQ_OP_SRC_PID_MASK);
	val = u32_replace_bits(val, ctrl_para->src_qid,
			       B_AX_CPUQ_OP_SRC_QID_MASK);
	val = u32_replace_bits(val, ctrl_para->dst_pid,
			       B_AX_CPUQ_OP_DST_PID_MASK);
	val = u32_replace_bits(val, ctrl_para->dst_qid,
			       B_AX_CPUQ_OP_DST_QID_MASK);
	rtw89_write32(rtwdev, reg, val);

	reg = wd ? R_AX_WD_CPUQ_OP_0 : R_AX_PL_CPUQ_OP_0;
	val = 0;
	val = u32_replace_bits(val, cmd_type,
			       B_AX_CPUQ_OP_CMD_TYPE_MASK);
	val = u32_replace_bits(val, ctrl_para->macid,
			       B_AX_CPUQ_OP_MACID_MASK);
	val = u32_replace_bits(val, ctrl_para->pkt_num,
			       B_AX_CPUQ_OP_PKTNUM_MASK);
	val |= B_AX_CPUQ_OP_EXEC;
	rtw89_write32(rtwdev, reg, val);

	reg = wd ? R_AX_WD_CPUQ_OP_STATUS : R_AX_PL_CPUQ_OP_STATUS;
	timeout = 2000;
	while (timeout--) {
		val = rtw89_read32(rtwdev, reg);
		if (val & B_AX_CPUQ_OP_STAT_DONE)
			break;
		udelay(1);
	}

	if (!++timeout)
		return -EBUSY;
/*
	if (cmd_type == CPUIO_OP_CMD_GET_1ST_PID ||
	    cmd_type == CPUIO_OP_CMD_GET_NEXT_PID)
		ctrl_para->pktid = FIELD_GET(B_AX_WD_CPUQ_OP_PKTID_MASK, val);
*/

	return 0;
}

static int dle_quota_change(struct rtw89_dev *rtwdev, enum rtw89_qta_mode mode)
{
	struct rtw89_dle_mem *cfg;
	struct rtw89_cpuio_ctrl ctrl_para = {0};
	u16 pkt_id;
	int ret;

	cfg = get_dle_mem_cfg(rtwdev, mode);
	if (!cfg) {
		rtw89_err(rtwdev, "[ERR]wd/dle mem cfg\n");
		return -EINVAL;
	}

	if (dle_used_size(cfg->wde_size, cfg->ple_size) !=
			  rtwdev->chip->fifo_size) {
		rtw89_err(rtwdev, "[ERR]wd/dle mem cfg\n");
		return -EINVAL;
	}

	dle_quota_cfg(rtwdev, cfg);

	pkt_id = rtw89_mac_dle_buf_req(rtwdev, 0x20, true);
	if (pkt_id == 0xffff) {
		rtw89_err(rtwdev, "[ERR]WDE DLE buf req\n");
		return -ENOMEM;
	}

	ctrl_para.cmd_type = CPUIO_OP_CMD_ENQ_TO_HEAD;
	ctrl_para.start_pktid = pkt_id;
	ctrl_para.end_pktid = pkt_id;
	ctrl_para.pkt_num = 0;
	ctrl_para.dst_pid = WDE_DLE_PORT_ID_WDRLS;
	ctrl_para.dst_qid = WDE_DLE_QUEID_NO_REPORT;
	ret = rtw89_mac_set_cpuio(rtwdev, &ctrl_para, true);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]WDE DLE enqueue to head\n");
		return -EFAULT;
	}

	pkt_id = rtw89_mac_dle_buf_req(rtwdev, 0x20, false);
	if (pkt_id == 0xffff) {
		rtw89_err(rtwdev, "[ERR]PLE DLE buf req\n");
		return -ENOMEM;
	}

	ctrl_para.cmd_type = CPUIO_OP_CMD_ENQ_TO_HEAD;
	ctrl_para.start_pktid = pkt_id;
	ctrl_para.end_pktid = pkt_id;
	ctrl_para.pkt_num = 0;
	ctrl_para.dst_pid = PLE_DLE_PORT_ID_PLRLS;
	ctrl_para.dst_qid = PLE_DLE_QUEID_NO_REPORT;
	ret = rtw89_mac_set_cpuio(rtwdev, &ctrl_para, false);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]PLE DLE enqueue to head\n");
		return -EFAULT;
	}

	return 0;
}

static int band1_enable(struct rtw89_dev *rtwdev)
{
	int ret, i;
	u32 sleep_bak[4] = {0};
	u32 pause_bak[4] = {0};
	u16 tx_en;
	u16 tx_en_mask;

	ret = stop_sch_tx(rtwdev, 0, &tx_en, &tx_en_mask);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]stop sch tx %d\n", ret);
		return ret;
	}

	for (i = 0; i < 4; i++) {
		sleep_bak[i] = rtw89_read32(rtwdev, R_AX_MACID_SLEEP_0 + i * 4);
		pause_bak[i] = rtw89_read32(rtwdev, R_AX_SS_MACID_PAUSE_0 + i * 4);
		rtw89_write32(rtwdev, R_AX_MACID_SLEEP_0 + i * 4, U32_MAX);
		rtw89_write32(rtwdev, R_AX_SS_MACID_PAUSE_0 + i * 4, U32_MAX);
	}

	//TODO: for 8852a, a cut only, add tx_idle_poll_band?
	ret = tx_idle_ck(rtwdev, 0);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]tx idle poll %d\n", ret);
		return ret;
	}

	ret = dle_quota_change(rtwdev, rtwdev->mac.dle_info.qta_mode);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]DLE quota change %d\n", ret);
		return ret;
	}

	for (i = 0; i < 4; i++) {
		rtw89_write32(rtwdev, R_AX_MACID_SLEEP_0 + i * 4, sleep_bak[i]);
		rtw89_write32(rtwdev, R_AX_SS_MACID_PAUSE_0 + i * 4, pause_bak[i]);
	}

	ret = resume_sch_tx(rtwdev, 0, tx_en, tx_en_mask);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC1 resume sch tx %d\n", ret);
		return ret;
	}

	ret = cmac_func_en(rtwdev, 1, true);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC1 func en %d\n", ret);
		return ret;
	}

	ret = cmac_init(rtwdev, 1);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC1 init %d\n", ret);
		return ret;
	}

	rtw89_write32_set(rtwdev, R_AX_SYS_ISO_CTRL_EXTEND,
			  B_AX_R_SYM_FEN_WLPHYFUN_1 | B_AX_R_SYM_FEN_WLPHYGLB_1);

	return 0;
}

static int rtw89_mac_enable_imr(struct rtw89_dev *rtwdev, u8 band,
				enum rtw89_mac_hwmod_sel sel)
{
	u32 reg, val;
	int ret;

	ret = rtw89_mac_check_mac_en(rtwdev, band, sel);
	if (ret) {
		rtw89_err(rtwdev, "MAC%d band%d is not ready\n", sel, band);
		return ret;
	}

	if (sel == RTW89_DMAC_SEL) {
		rtw89_write32_clr(rtwdev, R_AX_TXPKTCTL_ERR_IMR_ISR,
				  B_AX_TXPKTCTL_USRCTL_RLSBMPLEN_ERR_INT_EN |
				  B_AX_TXPKTCTL_USRCTL_RDNRLSCMD_ERR_INT_EN);
		rtw89_write32_clr(rtwdev, R_AX_TXPKTCTL_ERR_IMR_ISR_B1,
				  B_AX_TXPKTCTL_USRCTL_RLSBMPLEN_ERR_INT_EN |
				  B_AX_TXPKTCTL_USRCTL_RDNRLSCMD_ERR_INT_EN);
		rtw89_write32_clr(rtwdev, R_AX_HOST_DISPATCHER_ERR_IMR,
				  B_AX_HDT_PKT_FAIL_DBG_INT_EN |
				  B_AX_HDT_OFFSET_UNMATCH_INT_EN);
		rtw89_write32_clr(rtwdev, R_AX_CPU_DISPATCHER_ERR_IMR,
				  B_AX_CPU_SHIFT_EN_ERR_INT_EN);
		rtw89_write32_clr(rtwdev, R_AX_PLE_ERR_IMR,
				  B_AX_PLE_GETNPG_STRPG_ERR_INT_EN);
	} else if (sel == RTW89_CMAC_SEL) {
		reg = rtw89_mac_reg_by_band(R_AX_SCHEDULE_ERR_IMR, band);
		rtw89_write32_clr(rtwdev, reg,
				  B_AX_SORT_NON_IDLE_ERR_INT_EN);

		reg = rtw89_mac_reg_by_band(R_AX_DLE_CTRL, band);
		rtw89_write32_clr(rtwdev, reg,
				  B_AX_NO_RESERVE_PAGE_ERR_IMR);

		reg = rtw89_mac_reg_by_band(R_AX_PTCL_IMR0, band);
		val = B_AX_F2PCMD_USER_ALLC_ERR_INT_EN |
		      B_AX_TX_RECORD_PKTID_ERR_INT_EN |
		      B_AX_FSM_TIMEOUT_ERR_INT_EN;
		rtw89_write32(rtwdev, reg, val);

		reg = rtw89_mac_reg_by_band(R_AX_PHYINFO_ERR_IMR, band);
		rtw89_write32_set(rtwdev, reg,
				  B_AXC_PHY_TXON_TIMEOUT_INT_EN |
				  B_AX_CCK_CCA_TIMEOUT_INT_EN |
				  B_AX_OFDM_CCA_TIMEOUT_INT_EN |
				  B_AX_DATA_ON_TIMEOUT_INT_EN |
				  B_AX_STS_ON_TIMEOUT_INT_EN |
				  B_AX_CSI_ON_TIMEOUT_INT_EN);
	} else {
		return -EINVAL;
	}

	return 0;
}

static int rtw89_mac_dbcc_enable(struct rtw89_dev *rtwdev, bool enable)
{
	int ret = 0;

	if (enable) {
		ret = band1_enable(rtwdev);
		if (ret) {
			rtw89_err(rtwdev, "[ERR] band1_enable %d\n", ret);
			return ret;
		}

		ret = rtw89_mac_enable_imr(rtwdev, 1, RTW89_CMAC_SEL);
		if (ret) {
			rtw89_err(rtwdev, "[ERR] enable CMAC1 IMR %d\n", ret);
			return ret;
		}
	} else {
		rtw89_err(rtwdev, "[ERR] disable dbcc is not implemented not\n");
		return -EINVAL;
	}

	return 0;
}

static int rtw89_mac_trx_init(struct rtw89_dev *rtwdev)
{
	enum rtw89_qta_mode qta_mode = rtwdev->mac.dle_info.qta_mode;
	int ret;

	pr_info("%s: dmac_init\n", __func__);
	ret = dmac_init(rtwdev, 0);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]DMAC init %d\n", ret);
		return ret;
	}

	pr_info("%s: cmac_init\n", __func__);
	ret = cmac_init(rtwdev, 0);
	if (ret) {
		rtw89_err(rtwdev, "[ERR]CMAC%d init %d\n", 0, ret);
		return ret;
	}

	if (qta_mode == RTW89_QTA_DBCC || qta_mode == RTW89_QTA_DBCC_WD128 ||
	    qta_mode == RTW89_QTA_DBCC_STF || qta_mode == RTW89_QTA_SU_TP ||
	    qta_mode == RTW89_QTA_BCN_TEST) {
		pr_info("%s: rtw89_mac_dbcc_enable\n", __func__);
		ret = rtw89_mac_dbcc_enable(rtwdev, true);
		if (ret) {
			rtw89_err(rtwdev, "[ERR]dbcc_enable init %d\n", ret);
			return ret;
		}
	}

	pr_info("%s: rtw89_mac_enable_imr: DMAC\n", __func__);
	ret = rtw89_mac_enable_imr(rtwdev, 0, RTW89_DMAC_SEL);
	if (ret) {
		rtw89_err(rtwdev, "[ERR] enable DMAC IMR %d\n", ret);
		return ret;
	}

	pr_info("%s: rtw89_mac_enable_imr: CMAC\n", __func__);
	ret = rtw89_mac_enable_imr(rtwdev, 0, RTW89_CMAC_SEL);
	if (ret) {
		rtw89_err(rtwdev, "[ERR] to enable CMAC0 IMR %d\n", ret);
		return ret;
	}

	if (rtwdev->hci.type == RTW89_HCI_TYPE_PCIE) {
		u32 val;

		val = rtw89_read32(rtwdev, R_AX_RLSRPT0_CFG1);
		val = u32_replace_bits(val, 121, B_AX_RLSRPT0_AGGNUM_MASK);
		val = u32_replace_bits(val, 255, B_AX_RLSRPT0_TO_MASK);
		rtw89_write32(rtwdev, R_AX_RLSRPT0_CFG1, val);
	}

	pr_info("%s <===\n", __func__);
	return 0;
}

static int rtw89_mac_enable_cpu(struct rtw89_dev *rtwdev, u8 boot_reason,
				bool dlfw)
{
	u32 val;
	int ret;

	if (rtw89_read32(rtwdev, R_AX_PLATFORM_ENABLE) & B_AX_WCPU_EN)
		return -EFAULT;

	rtw89_write32_set(rtwdev, R_AX_SYS_CLK_CTRL, B_AX_CPU_CLK_EN);

	val = rtw89_read32(rtwdev, R_AX_WCPU_FW_CTRL);
	val &= ~(B_AX_WCPU_FWDL_EN | B_AX_H2C_PATH_RDY | B_AX_FWDL_PATH_RDY);
	val = u32_replace_bits(val, RTW89_FWDL_INITIAL_STATE,
			       B_AX_WCPU_FWDL_STS_MASK);

	if (dlfw)
		val |= B_AX_WCPU_FWDL_EN;

	rtw89_write32(rtwdev, R_AX_WCPU_FW_CTRL, val);
	rtw89_write16_mask(rtwdev, R_AX_BOOT_REASON, B_AX_BOOT_REASON_MASK,
			   boot_reason);
	rtw89_write32_set(rtwdev, R_AX_PLATFORM_ENABLE, B_AX_WCPU_EN);

	if (!dlfw) {
		mdelay(5);

		ret = rtw89_fw_check_rdy(rtwdev);
		if (ret)
			return ret;
	}

	return 0;
}

int rtw89_mac_init(struct rtw89_dev *rtwdev)
{
	int ret;

	ret = rtw89_mac_power_switch(rtwdev, true);
	if (ret) {
		rtw89_mac_power_switch(rtwdev, false);
		ret = rtw89_mac_power_switch(rtwdev, true);
		if (ret)
			return ret;
	}

	hci_func_en(rtwdev);
	if (rtwdev->hci.ops->mac_pre_init) {
		ret = rtwdev->hci.ops->mac_pre_init(rtwdev);
		if (ret)
			return ret;
	}

	ret = rtw89_fwdl_pre_init(rtwdev, rtwdev->mac.dle_info.qta_mode);
	if (ret)
		return ret;

	pr_info("%s: stop here first\n", __func__);
	return -EINVAL;

	ret = rtw89_mac_enable_cpu(rtwdev, 0, true);
	if (ret)
		return ret;

	ret = rtw89_mac_sys_init(rtwdev);
	if (ret)
		return ret;

	ret = rtw89_mac_trx_init(rtwdev);
	if (ret)
		return ret;

	ret = rtw89_fw_wait_completion(rtwdev);
	if (ret)
		return ret;

	ret = rtw89_fw_download(rtwdev);
	if (ret)
		return ret; 

	ret = rtw89_efuse_process(rtwdev);
	if (ret)
		return ret;

	pr_info("reset bb\n");
	rtwdev->chip->ops->phy_set_param(rtwdev);


	if (rtwdev->hci.ops->mac_post_init) {
		ret = rtwdev->hci.ops->mac_post_init(rtwdev);
		if (ret)
			return ret;
	}
	rtwdev->hci.ops->reset(rtwdev);

	return ret;
}


int rtw89_mac_send_h2c(struct rtw89_dev *rtwdev, const u8 *h2c_pkt, u32 len,
		       u8 cat, u8 cl, u8 func, bool is_fwdl)
{
	struct rtw89_fw_info *fw_info = &rtwdev->fw;
	struct rtw89_fw_cmd_hdr *fc_hdr;
	struct rtw89_txdesc_wd_body *wd_body;
	struct sk_buff *skb;
	int headsize = RTW89_FWCMD_HDR_LEN + RTW89_TX_WD_BODY_LEN;
	int ret = 0;

	if (rtwdev->debug)
		pr_info("%s H2C: %x %x %x\n", __func__, cl, func, len);

	skb = dev_alloc_skb(len + headsize);
	if (unlikely(!skb))
		return -ENOMEM;

	skb_reserve(skb, headsize);
	skb_put_data(skb, h2c_pkt, len);

	/* FWCMD HDR */
	skb_push(skb, RTW89_FWCMD_HDR_LEN);
	memset(skb->data, 0, RTW89_FWCMD_HDR_LEN);
	fc_hdr = (struct rtw89_fw_cmd_hdr *)skb->data;
	fc_hdr->del_type = RTW89_FWCMD_TYPE_H2C;
	fc_hdr->cat = cat;
	fc_hdr->cl = cl;
	fc_hdr->func = func;
	fc_hdr->h2c_seq = fw_info->h2c_seq;
	if (!is_fwdl)
		fc_hdr->rec_ack = !(fw_info->h2c_seq & 0x3);
	fc_hdr->len = len + RTW89_FWCMD_HDR_LEN;

	/* TXDESC */
	skb_push(skb, RTW89_TX_WD_BODY_LEN);
	memset(skb->data, 0, RTW89_TX_WD_BODY_LEN);
	wd_body = (struct rtw89_txdesc_wd_body *)skb->data;
	wd_body->ch_dma = RTW89_DMA_H2C;
	wd_body->txpktsize = len + RTW89_FWCMD_HDR_LEN;

	ret = rtw89_hci_write_data_h2c(rtwdev, skb);
	if (unlikely(ret))
		goto err_free_skb;

	return ret;

err_free_skb:
	dev_kfree_skb(skb);

	return ret;
}
