// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */
#include "core.h"
#include "debug.h"
#include "reg.h"
#include "fw.h"

#define FWDL_WAIT_CNT 400000
int rtw89_fw_check_rdy(struct rtw89_dev *rtwdev)
{
	u8 val;
	u32 cnt = FWDL_WAIT_CNT;

	while (--cnt) {
		val = FIELD_GET(B_AX_WCPU_FWDL_STS_MASK,
				rtw89_read8(rtwdev, R_AX_WCPU_FW_CTRL));
		if (val == RTW89_FWDL_WCPU_FW_INIT_RDY)
			break;
		udelay(1);
	}

	if (!cnt) {
		switch (val) {
		case RTW89_FWDL_CHECKSUM_FAIL:
			rtw89_err(rtwdev, "fw checksum fail\n");
			return -EINVAL;

		case RTW89_FWDL_SECURITY_FAIL:
			rtw89_err(rtwdev, "fw security fail\n");
			return -EINVAL;

		case RTW89_FWDL_CUT_NOT_MATCH:
			rtw89_err(rtwdev, "fw cut not match\n");
			return -EINVAL;

		default:
			return -EBUSY;
		}
	}

	return 0;
}

static int rtw89_fw_hdr_parser(struct rtw89_dev *rtwdev, u8 *fw, u32 len,
			       struct rtw89_fw_bin_info *info)
{
	struct rtw89_fw_hdr *hdr;
	struct rtw89_fw_hdr_section *section;
	struct rtw89_fw_hdr_section_info *section_info;
	u8 *fw_end = fw + len;
	u8 *bin_ptr;
	u32 i;

	if (!info)
		return -EINVAL;

	hdr = (struct rtw89_fw_hdr *)fw;
	info->section_num = le32_to_cpu(hdr->sec_num);
	info->hdr_len = sizeof(struct rtw89_fw_hdr) +
			info->section_num * sizeof(struct rtw89_fw_hdr_section);
	hdr->fw_part_sz = cpu_to_le32(FWDL_SECTION_PER_PKT_LEN);

	bin_ptr = fw + info->hdr_len;

	/* jump to section header */
	fw += sizeof(struct rtw89_fw_hdr);
	section_info = info->section_info;
	for (i = 0; i < info->section_num; i++) {
		section = (struct rtw89_fw_hdr_section *)fw;
		section_info->len = le32_to_cpu(section->sec_size);
		if (le32_to_cpu(section->checksum))
			section_info->len += FWDL_SECTION_CHKSUM_LEN;
		section_info->redl = le32_to_cpu(section->redl);
		section_info->dladdr =
				le32_to_cpu(section->dl_addr) & 0x1fffffff;

		section_info->addr = bin_ptr;
		bin_ptr += section_info->len;
		fw += sizeof(struct rtw89_fw_hdr_section);
		section_info++;
	}

	if (fw_end != bin_ptr) {
		rtw89_err(rtwdev, "[ERR]fw bin size\n");
		return -EINVAL;
	}

	return 0;
}

static void rtw89_fw_update_ver(struct rtw89_dev *rtwdev,
				struct rtw89_fw_hdr *hdr)
{
	struct rtw89_fw_info *fw_info = &rtwdev->fw;

	fw_info->ver = le32_to_cpu(hdr->version);
	fw_info->sub_ver = le32_to_cpu(hdr->subversion);
	fw_info->sub_idex = le32_to_cpu(hdr->subindex);
	fw_info->build_year = le32_to_cpu(hdr->year);
	fw_info->build_mon = le32_to_cpu(hdr->month);
	fw_info->build_date = le32_to_cpu(hdr->date);
	fw_info->build_hour = le32_to_cpu(hdr->hour);
	fw_info->build_min = le32_to_cpu(hdr->min);
	fw_info->h2c_seq = 0;
	fw_info->rec_seq = 0;
}

int rtw89_fw_download(struct rtw89_dev *rtwdev, u8 *fw, u32 len)
{
	struct rtw89_fw_bin_info info;
	u32 cnt = FWDL_WAIT_CNT;
	int ret;

	ret = rtw89_fw_hdr_parser(rtwdev, fw, len, &info);
	if (ret) {
		rtw89_err(rtwdev, "parse fw header fail\n");
		goto fwdl_err;
	}

	rtw89_fw_update_ver(rtwdev, (struct rtw89_fw_hdr *)fw);

	while (--cnt) {
		if (rtw89_read8(rtwdev, R_AX_WCPU_FW_CTRL) & B_AX_H2C_PATH_RDY)
			break;
		udelay(1);
	}
	if (!cnt) {
		rtw89_err(rtwdev, "[ERR]H2C path ready\n");
		ret = -EBUSY;
		goto fwdl_err;
	}

fwdl_err:
	return ret;
}
