// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include "core.h"
#include "rtw8852a.h"

static const struct rtw89_chip_ops rtw8852a_chip_ops = {
};

const struct rtw89_chip_info rtw8852a_chip_info = {
	.ops		= &rtw8852a_chip_ops,
	.fifo_size	= 458752,
};
EXPORT_SYMBOL(rtw8852a_chip_info);
