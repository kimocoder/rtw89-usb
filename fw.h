/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#ifndef __RTW89_FW_H__
#define __RTW89_FW_H__

enum rtw89_fw_dl_status {
	RTW89_FWDL_INITIAL_STATE = 0,
	RTW89_FWDL_FWDL_ONGOING = 1,
	RTW89_FWDL_CHECKSUM_FAIL = 2,
	RTW89_FWDL_SECURITY_FAIL = 3,
	RTW89_FWDL_CUT_NOT_MATCH = 4,
	RTW89_FWDL_RSVD0 = 5,
	RTW89_FWDL_WCPU_FWDL_RDY = 6,
	RTW89_FWDL_WCPU_FW_INIT_RDY = 7
};

#define FWDL_SECTION_MAX_NUM 10
#define FWDL_SECTION_CHKSUM_LEN	8
#define FWDL_SECTION_PER_PKT_LEN 2020

struct rtw89_fw_hdr_section_info {
	u8 redl;
	u8 *addr;
	u32 len;
	u32 dladdr;
};

struct rtw89_fw_bin_info {
	u8 section_num;
	u32 hdr_len;
	struct rtw89_fw_hdr_section_info section_info[FWDL_SECTION_MAX_NUM];
};

struct rtw89_fw_hdr_section {
	/* dword0 */
	u32 dl_addr;
	/* dword1 */
	u32 sec_size:24;
	u8 section_type:4;
	u8 checksum:1;
	u8 redl:1;
	u8 res0:2;
	/* dword2 */
	u32 res1;
	/* dword3 */
	u32 res2;
} __packed;

struct rtw89_fw_hdr {
	/* dword0 */
	u8 cut_id;
	u32 chip_id:24;
	/* dword1 */
	u16 version:12;
	u8 version_top:4;
	u8 subversion;
	u8 subindex;
	/* dword2 */
	u32 commit_id;
	/* dword3 */
	u8 sec_hdr_offset;
	u8 sec_hdr_sz;
	u8 fw_hdr_sz;
	u8 fw_hdr_ver;
	/* dword4 */
	u8 month;
	u8 date;
	u8 hour;
	u8 min;
	/* dword5 */
	u32 year;
	/* dword6 */
	u8 image_from:2;
	u8 res0:2;
	u8 boot_from:2;
	u8 rom_only:1;
	u8 fw_type:1;
	u8 sec_num;
	u8 hci_type:4;
	u8 net_type:4;
	u8 res1;
	/* dword7 */
	u16 fw_part_sz;
	u8 res2;
	u8 cmd_ver;
} __packed;

int rtw89_fw_check_rdy(struct rtw89_dev *rtwdev);
int rtw89_fw_request(struct rtw89_dev *rtwdev);
int rtw89_fw_wait_completion(struct rtw89_dev *rtwdev);
int rtw89_fw_download(struct rtw89_dev *rtwdev);

#endif
