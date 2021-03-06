// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */
#include "core.h"
#include "debug.h"
#include "reg.h"
#include "txrx.h"
#include "mac.h"
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

	pr_info("%s: cnt=%u, val=%u\n", __func__, cnt, val);
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

static int rtw89_fw_sec_send_h2c(struct rtw89_dev *rtwdev,
				 const u8 *h2c_pkt, u32 len)
{
	struct rtw89_txdesc_wd_body *wd_body;
	struct sk_buff *skb;
	int headsize = RTW89_TX_WD_BODY_LEN;
	int ret = 0;

	skb = dev_alloc_skb(len + headsize);
	if (unlikely(!skb))
		return -ENOMEM;

	skb_reserve(skb, headsize);
	skb_put_data(skb, h2c_pkt, len);

	/* TXDESC */
	skb_push(skb, RTW89_TX_WD_BODY_LEN);
	memset(skb->data, 0, RTW89_TX_WD_BODY_LEN);
	wd_body = (struct rtw89_txdesc_wd_body *)skb->data;
	wd_body->ch_dma = RTW89_DMA_H2C;
	wd_body->fwdl_en = 1;
	wd_body->txpktsize = len;

	ret = rtw89_hci_write_data_h2c(rtwdev, skb);
	if (unlikely(ret))
		goto err_free_skb;

	return ret;

err_free_skb:
	dev_kfree_skb(skb);

	return ret;
}

static int rtw89_fw_poll_ready(struct rtw89_dev *rtwdev, u8 rbit)
{
	u32 cnt = FWDL_WAIT_CNT;

	while (--cnt) {
		if (rtw89_read8(rtwdev, R_AX_WCPU_FW_CTRL) & rbit)
			break;
		udelay(1);
	}

	if (!cnt) {
		rtw89_err(rtwdev, "[ERR]H2C path ready\n");
		return -EBUSY;
	}

	return 0;
}

static int rtw89_fwdl_phase0(struct rtw89_dev *rtwdev)
{
	int ret;

	ret = rtw89_fw_poll_ready(rtwdev, B_AX_H2C_PATH_RDY);

	return ret;
}

static int rtw89_fwdl_phase1(struct rtw89_dev *rtwdev)
{
	struct rtw89_fw_info *fw_info = &rtwdev->fw;
	struct rtw89_fw_bin_info *bin_info = fw_info->bin_info;
	const struct firmware *firmware = fw_info->firmware;
	bool is_fwdl = true;
	const u8 *buf;
	int len;
	int ret;

	buf = firmware->data;
	len = bin_info->hdr_len;
	ret = rtw89_mac_send_h2c(rtwdev, buf, len,
				 RTW89_FWCMD_H2C_CAT_MAC,
				 RTW89_FWCMD_H2C_CL_FWDL,
				 RTW89_FWCMD_H2C_FUNC_FWHDR_DL, is_fwdl);
	if (unlikely(ret))
		return ret;

	ret = rtw89_fw_poll_ready(rtwdev, B_AX_H2C_PATH_RDY);
	return ret;
}

static u32 rtw89_fw_sections_download(struct rtw89_dev *rtwdev,
				      struct rtw89_fw_hdr_section_info *info)
{
	u8 *section = info->addr;
	u32 residue_len = info->len;
	u32 pkt_len;
	u32 ret;

	while (residue_len) {
		if (residue_len >= FWDL_SECTION_PER_PKT_LEN)
			pkt_len = FWDL_SECTION_PER_PKT_LEN;
		else
			pkt_len = residue_len;

		ret = rtw89_fw_sec_send_h2c(rtwdev, section, pkt_len);
		if (unlikely(ret)) {
			rtw89_err(rtwdev, "failed to send FW section h2c\n");
			return ret;
		}

		section += pkt_len;
		residue_len -= pkt_len;
	}

	return 0;
}

static int rtw89_fwdl_phase2(struct rtw89_dev *rtwdev)
{
	struct rtw89_fw_info *fw_info = &rtwdev->fw;
	struct rtw89_fw_bin_info *bin_info = fw_info->bin_info;
	struct rtw89_fw_hdr_section_info *section_info = bin_info->section_info;
	u32 section_num = bin_info->section_num;
	int ret;

	while (section_num > 0) {
		ret =  rtw89_fw_sections_download(rtwdev, section_info);
		if (unlikely(ret))
			return ret;

		section_info++;
		section_num--;
	}

	mdelay(5);
	ret = rtw89_fw_check_rdy(rtwdev);
	pr_info("FW check rdy: ret=%d\n", ret);
	return ret;
}

int rtw89_fw_download(struct rtw89_dev *rtwdev)
{
	int ret;

	ret = rtw89_fwdl_phase0(rtwdev);
	if (unlikely(ret))
		return ret;

	ret = rtw89_fwdl_phase1(rtwdev);
	if (unlikely(ret))
		return ret;

	ret = rtw89_fwdl_phase2(rtwdev);
	if (unlikely(ret))
		return ret;

	return 0;
}

int rtw89_fw_wait_completion(struct rtw89_dev *rtwdev)
{
	struct rtw89_fw_info *fw_info = &rtwdev->fw;

	wait_for_completion(&fw_info->completion);
	if (!fw_info->firmware)
		return -EINVAL;

	return 0;
}

static void rtw89_fw_request_cb(const struct firmware *firmware, void *context)
{
	struct rtw89_fw_info *fw_info = context;
	struct rtw89_dev *rtwdev = fw_info->rtwdev;
	int ret;

	if (!firmware || !firmware->data) {
		rtw89_err(rtwdev, "failed to request firmware\n");
		goto err_out;
	}

	pr_info("%s: firmware size=%lu\n", __func__, firmware->size);
	fw_info->firmware = firmware;
	fw_info->bin_info = kmalloc(sizeof(*fw_info->bin_info), GFP_ATOMIC);
	if (!fw_info->bin_info) {
		rtw89_err(rtwdev, "failed to allocate bin_info\n");
		goto err_out;
	}

	ret = rtw89_fw_hdr_parser(rtwdev, (u8 *)firmware->data, firmware->size,
				  fw_info->bin_info);
	if (ret) {
		rtw89_err(rtwdev, "failed to parse fw header\n");
		goto err_free_bin_info;
	}

	rtw89_fw_update_ver(rtwdev, (struct rtw89_fw_hdr *)firmware->data);
	rtw89_info(rtwdev, "FW ver:%d.%d.%d\n",
		   fw_info->ver, fw_info->sub_ver, fw_info->sub_idex);
	rtw89_info(rtwdev, "FW build time: %d/%d/%d %d:%d\n",
		   fw_info->build_year, fw_info->build_mon, fw_info->build_date,
		   fw_info->build_hour, fw_info->build_min);

	complete_all(&fw_info->completion);

	return;

err_free_bin_info:
	kfree(fw_info->bin_info);

err_out:
	fw_info->firmware = NULL;
	complete_all(&fw_info->completion);
}

int rtw89_fw_request(struct rtw89_dev *rtwdev)
{
	struct rtw89_fw_info *fw_info = &rtwdev->fw;
	const char *fw_name = rtwdev->chip->fw_name;
	int ret;

	fw_info->rtwdev = rtwdev;
	fw_info->bin_info = NULL;
	init_completion(&fw_info->completion);

	ret = request_firmware_nowait(THIS_MODULE, true, fw_name, rtwdev->dev,
			GFP_KERNEL, fw_info, rtw89_fw_request_cb);
	if (ret) {
		rtw89_err(rtwdev, "failed to async firmware request\n");
		return ret;
	}

	return 0;
}

int rtw89_fwdl_pre_init(struct rtw89_dev *rtwdev, enum rtw89_qta_mode mode)
{
	u32 val32;
	int ret;

	val32 = B_AX_MAC_FUNC_EN | B_AX_DMAC_FUNC_EN | B_AX_DISPATCHER_EN |
		B_AX_PKT_BUF_EN;
	rtw89_write32(rtwdev, R_AX_DMAC_FUNC_EN, val32);
	rtw89_write32(rtwdev, R_AX_DMAC_CLK_EN, B_AX_DISPATCHER_CLK_EN);

	ret = rtw89_mac_dle_init(rtwdev, RTW89_QTA_DLFW, mode);
	if (ret) {
		rtw89_err(rtwdev, "fail to DLE init %d\n", ret);
		return ret;
	}

	ret = rtw89_mac_hfc_init(rtwdev, 1, 0, 1);
	if (ret) {
		rtw89_err(rtwdev, "fail to HFC init %d\n", ret);
		return ret;
	}

	return ret;
}

