/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#ifndef __RTW_PHY_H_
#define __RTW_PHY_H_

#include "debug.h"

void rtw89_phy_load_tables(struct rtw89_dev *rtwdev);
void rtw89_phy_cfg_bb(struct rtw89_dev *rtwdev, const struct rtw89_table *tbl,
		      u32 addr, u32 data);
void rtw89_parse_tbl_phy_cond(struct rtw89_dev *rtwdev,
			      const struct rtw89_table *tbl);

#define RTW89_DECL_TABLE_PHY_COND_CORE(name, cfg, path)	\
const struct rtw89_table name ## _tbl = {			\
	.data = name,					\
	.size = ARRAY_SIZE(name),			\
	.parse = rtw89_parse_tbl_phy_cond,		\
	.do_cfg = cfg,					\
	.rf_path = path,				\
}

#define RTW89_DECL_TABLE_PHY_COND(name, cfg)		\
	RTW89_DECL_TABLE_PHY_COND_CORE(name, cfg, 0)


#endif
