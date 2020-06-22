/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2020  Realtek Corporation
 */

#ifndef __RTW89_TXRX_H__
#define __RTW89_TXRX_H__

#define RTW89_TX_WD_BODY_LEN	24
#define RTW89_TX_WD_INFO_LEN	24

struct rtw89_txdesc_wd_body {
	/* dword0 */
	u8 hwseq_mode_en:2;
	u8 hwssn_sel:2;
	u8 smh_en:1;
	u8 hwamsdu:1;
	u8 hw_aes_iv:1;
	u8 wd_page:1;
	u8 chk_en:1;
	u8 wp_int:1;
	u8 stf_mode:1;
	u8 hdr_llc_len:5;
	u8 ch_dma:4;
	u8 fwdl_en:1;
	u8 pkt_offset:1;
	u8 wdinfo_en:1;
	u8 moredata:1;
	u8 wp_offset;

	/* dword1 */
	u8 shcut_camid;
	u8 dma_txagg_num;
	u8 resv1:4;
	u16 pld:12;

	/* dword2 */
	u32 txpktsize:14;
	u32 ru_tc:3;
	u32 qsel:6;
	u32 tid_ind:1;
	u32 macid:7;
	u32 resv2:1;

	/* dword3 */
	u32 wifi_seq:12;
	u32 agg_en:1;
	u32 bk:1;
	u32 rts_tc:6;
	u32 data_tc:6;
	u32 mu_2nd_tc:3;
	u32 mu_tc:3;

	/* dword4 */
	u16 checksum;
	u16 aes_iv_l;

	/* dword5 */
	u32 aes_iv_h;
} __packed;

/* TX WD BODY DWORD 0 */
#define RTW89_TXWD_WP_OFFSET		GENMASK(31, 24)
#define RTW89_TXWD_MORE_DATA		BIT(23)
#define RTW89_TXWD_WD_INFO_EN		BIT(22)
#define RTW89_TXWD_CHANNEL_DMA		GENMASK(19, 16)
#define RTW89_TXWD_HDR_LLC_LEN		GENMASK(15, 11)
#define RTW89_TXWD_WD_PAGE		BIT(7)
#define RTW89_TXWD_HW_AMSDU		BIT(5)

/* TX WD BODY DWORD 1 */
#define RTW89_TXWD_PAYLOAD_ID		GENMASK(31, 16)

/* TX WD BODY DWORD 2 */
#define RTW89_TXWD_MACID		GENMASK(30, 24)
#define RTW89_TXWD_TID_INDICATE		BIT(23)
#define RTW89_TXWD_QSEL			GENMASK(22, 17)
#define RTW89_TXWD_TXPKT_SIZE		GENMASK(13, 0)

/* TX WD BODY DWORD 3 */

/* TX WD BODY DWORD 4 */

/* TX WD BODY DWORD 5 */

/* TX WD INFO DWORD 0 */
#define RTW89_TXWD_USE_RATE		BIT(30)
#define RTW89_TXWD_DATA_RATE		GENMASK(24, 16)
#define RTW89_TXWD_DISDATAFB		BIT(10)

/* TX WD INFO DWORD 1 */

/* TX WD INFO DWORD 2 */

/* TX WD INFO DWORD 3 */

/* TX WD INFO DWORD 4 */

/* TX WD INFO DWORD 5 */

/* RX DESC helpers */
/* Short Descriptor */
#define RTW89_GET_RXD_LONG_RXD(rxdesc) \
	le32_get_bits(rxdesc->dword0, BIT(31))
#define RTW89_GET_RXD_DRV_INFO_SIZE(rxdesc) \
	le32_get_bits(rxdesc->dword0, GENMASK(30, 28))
#define RTW89_GET_RXD_RPKT_TYPE(rxdesc) \
	le32_get_bits(rxdesc->dword0, GENMASK(27, 24))
#define RTW89_GET_RXD_MAC_INFO_VALID(rxdesc) \
	le32_get_bits(rxdesc->dword0, BIT(23))
#define RTW89_GET_RXD_BB_SEL(rxdesc) \
	le32_get_bits(rxdesc->dword0, BIT(22))
#define RTW89_GET_RXD_HD_IV_LEN(rxdesc) \
	le32_get_bits(rxdesc->dword0, GENMASK(21, 16))
#define RTW89_GET_RXD_SHIFT(rxdesc) \
	le32_get_bits(rxdesc->dword0, GENMASK(15, 14))
#define RTW89_GET_RXD_PKT_SIZE(rxdesc) \
	le32_get_bits(rxdesc->dword0, GENMASK(13, 0))
#define RTW89_GET_RXD_BW(rxdesc) \
	le32_get_bits(rxdesc->dword1, GENMASK(31, 30))
#define RTW89_GET_RXD_DATA_RATE(rxdesc) \
	le32_get_bits(rxdesc->dword1, GENMASK(24, 16))
#define RTW89_GET_RXD_USER_ID(rxdesc) \
	le32_get_bits(rxdesc->dword1, GENMASK(15, 8))
#define RTW89_GET_RXD_SR_EN(rxdesc) \
	le32_get_bits(rxdesc->dword1, BIT(7))
#define RTW89_GET_RXD_PPDU_CNT(rxdesc) \
	le32_get_bits(rxdesc->dword1, GENMASK(6, 4))
#define RTW89_GET_RXD_PPDU_TYPE(rxdesc) \
	le32_get_bits(rxdesc->dword1, GENMASK(3, 0))
#define RTW89_GET_RXD_FREE_RUN_CNT(rxdesc) \
	le32_get_bits(rxdesc->dword2, GENMASK(31, 0))
#define RTW89_GET_RXD_ICV_ERR(rxdesc) \
	le32_get_bits(rxdesc->dword3, BIT(10))
#define RTW89_GET_RXD_CRC32_ERR(rxdesc) \
	le32_get_bits(rxdesc->dword3, BIT(9))
#define RTW89_GET_RXD_HW_DEC(rxdesc) \
	le32_get_bits(rxdesc->dword3, BIT(2))
#define RTW89_GET_RXD_SW_DEC(rxdesc) \
	le32_get_bits(rxdesc->dword3, BIT(1))
#define RTW89_GET_RXD_A1_MATCH(rxdesc) \
	le32_get_bits(rxdesc->dword3, BIT(0))

/* Long Descriptor */
#define RTW89_GET_RXD_FRAG(rxdesc) \
	le32_get_bits(rxdesc->dword4, GENMASK(31, 28))
#define RTW89_GET_RXD_SEQ(rxdesc) \
	le32_get_bits(rxdesc->dword4, GENMASK(27, 16))
#define RTW89_GET_RXD_ADDR_CAM_VLD(rxdesc) \
	le32_get_bits(rxdesc->dword5, BIT(28))
#define RTW89_GET_RXD_RX_PL_ID(rxdesc) \
	le32_get_bits(rxdesc->dword5, GENMASK(27, 24))
#define RTW89_GET_RXD_MAC_ID(rxdesc) \
	le32_get_bits(rxdesc->dword5, GENMASK(23, 16))
#define RTW89_GET_RXD_ADDR_CAM_ID(rxdesc) \
	le32_get_bits(rxdesc->dword5, GENMASK(15, 8))
#define RTW89_GET_RXD_SEC_CAM_ID(rxdesc) \
	le32_get_bits(rxdesc->dword5, GENMASK(7, 0))

#endif
