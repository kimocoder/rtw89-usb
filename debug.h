/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#ifndef __RTW89_DEBUG_H__
#define __RTW89_DEBUG_H__

enum rtw89_debug_mask {
	RTW89_DBG_TXRX,
};

void rtw89_debugfs_init(struct rtw89_dev *rtwdev);

#define rtw89_info(rtwdev, a...) dev_info(rtwdev->dev, ##a)
#define rtw89_warn(rtwdev, a...) dev_warn(rtwdev->dev, ##a)
#define rtw89_err(rtwdev, a...) dev_err(rtwdev->dev, ##a)
#define rtw89_debug(rtwdev, a...) __rtw89_debug(rtwdev, ##a)

#endif
