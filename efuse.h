/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#ifndef __RTW_EFUSE_H__
#define __RTW_EFUSE_H__

int rtw89_efuse_process(struct rtw89_dev *rtwdev);
bool rtw89_efuse_check_autoload(struct rtw89_dev *rtwdev);
int rtw89_parse_efuse_map(struct rtw89_dev *rtwdev);

#endif
