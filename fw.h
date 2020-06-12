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

/* FWCMD */
#define RTW89_FWCMD_HDR_LEN 8

/* FWCMD del_type */
#define RTW89_FWCMD_TYPE_H2C	0
#define RTW89_FWCMD_TYPE_C2H	1

/* FWCMD cat */
#define RTW89_FWCMD_H2C_CAT_TEST 0x0
#define RTW89_FWCMD_H2C_CAT_MAC 0x1
#define RTW89_FWCMD_H2C_CAT_OUTSRC 0x2

/* FWCMD cl */
#define RTW89_FWCMD_H2C_CL_FW_INFO 0x0
#define RTW89_FWCMD_H2C_CL_WOW 0x1
#define RTW89_FWCMD_H2C_CL_PS 0x2
#define RTW89_FWCMD_H2C_CL_FWDL 0x3
#define RTW89_FWCMD_H2C_CL_TWT 0x4
#define RTW89_FWCMD_H2C_CL_FR_EXCHG 0x5
#define RTW89_FWCMD_H2C_CL_ADDR_CAM_UPDATE 0x6
#define RTW89_FWCMD_H2C_CL_BSSID_CAM_UPDATE 0x7
#define RTW89_FWCMD_H2C_CL_MEDIA_RPT 0x8
#define RTW89_FWCMD_H2C_CL_FW_OFLD 0x9
#define RTW89_FWCMD_H2C_CL_SEC_CAM 0xA
#define RTW89_FWCMD_H2C_CL_SOUND 0xB
#define RTW89_FWCMD_H2C_CL_BA_CAM 0xC
#define RTW89_FWCMD_H2C_CL_IE_CAM 0xD

/* FWCMD class 3 fwdl */
#define RTW89_FWCMD_H2C_FUNC_FWHDR_DL 0x0
#define RTW89_FWCMD_H2C_FUNC_FWHDR_REDL 0x1

struct rtw89_fw_cmd_hdr {
	/* dword0 */
	u8 cat:2;
	u8 cl:6;
	u8 func;
	u8 del_type;
	u8 h2c_seq;
	/* dword1 */
	u16 len:14;
	u8 rec_ack:1;
	u8 done_ack:1;
	u8 seq_valid:1;
	u8 seq:3;
	u8 seq_stop:1;
	u16 res1:12;
} __packed;

int rtw89_fw_check_rdy(struct rtw89_dev *rtwdev);
int rtw89_fw_request(struct rtw89_dev *rtwdev);
int rtw89_fw_wait_completion(struct rtw89_dev *rtwdev);
int rtw89_fw_download(struct rtw89_dev *rtwdev);

#endif
