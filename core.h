/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#ifndef __RTW89_CORE_H__
#define __RTW89_CORE_H__

#include <net/mac80211.h>
#include <linux/bitfield.h>
#include <linux/firmware.h>

/**
 * read_poll_timeout - Periodically poll an address until a condition is
 *			met or a timeout occurs
 * @op: accessor function (takes @args as its arguments)
 * @val: Variable to read the value into
 * @cond: Break condition (usually involving @val)
 * @sleep_us: Maximum time to sleep between reads in us (0
 *            tight-loops).  Should be less than ~20ms since usleep_range
 *            is used (see Documentation/timers/timers-howto.rst).
 * @timeout_us: Timeout in us, 0 means never timeout
 * @sleep_before_read: if it is true, sleep @sleep_us before read.
 * @args: arguments for @op poll
 *
 * Returns 0 on success and -ETIMEDOUT upon a timeout. In either
 * case, the last read value at @args is stored in @val. Must not
 * be called from atomic context if sleep_us or timeout_us are used.
 *
 * When available, you'll probably want to use one of the specialized
 * macros defined below rather than this macro directly.
 */
#define read_poll_timeout(op, val, cond, sleep_us, timeout_us, \
				sleep_before_read, args...) \
({ \
	u64 __timeout_us = (timeout_us); \
	unsigned long __sleep_us = (sleep_us); \
	ktime_t __timeout = ktime_add_us(ktime_get(), __timeout_us); \
	might_sleep_if((__sleep_us) != 0); \
	if (sleep_before_read && __sleep_us) \
		usleep_range((__sleep_us >> 2) + 1, __sleep_us); \
	for (;;) { \
		(val) = op(args); \
		if (cond) \
			break; \
		if (__timeout_us && \
		    ktime_compare(ktime_get(), __timeout) > 0) { \
			(val) = op(args); \
			break; \
		} \
		if (__sleep_us) \
			usleep_range((__sleep_us >> 2) + 1, __sleep_us); \
	} \
	(cond) ? 0 : -ETIMEDOUT; \
})

struct rtw89_dev;
struct rtw89_fw_bin_info;

extern const struct ieee80211_ops rtw89_ops;
extern const struct rtw89_chip_info rtw8852a_chip_info;

enum rtw89_hci_type {
	RTW89_HCI_TYPE_PCIE,
	RTW89_HCI_TYPE_USB,
	RTW89_HCI_TYPE_SDIO,
};

enum rtw89_core_chip_id {
	RTL8852A,
	RTL8852B,
};

enum rtw89_core_tx_type {
	RTW89_CORE_TX_TYPE_DATA,
	RTW89_CORE_TX_TYPE_MGMT,
	RTW89_CORE_TX_TYPE_FWCMD,
};

enum rtw89_core_rx_type {
	RTW89_CORE_RX_TYPE_WIFI		= 0,
	RTW89_CORE_RX_TYPE_PPDU_STAT	= 1,
	RTW89_CORE_RX_TYPE_CHAN_INFO	= 2,
	RTW89_CORE_RX_TYPE_BB_SCOPE	= 3,
	RTW89_CORE_RX_TYPE_F2P_TXCMD	= 4,
	RTW89_CORE_RX_TYPE_SS2FW	= 5,
	RTW89_CORE_RX_TYPE_TX_REPORT	= 6,
	RTW89_CORE_RX_TYPE_TX_REL_HOST	= 7,
	RTW89_CORE_RX_TYPE_DFS_REPORT	= 8,
	RTW89_CORE_RX_TYPE_TX_REL_CPU	= 9,
	RTW89_CORE_RX_TYPE_C2H		= 10,
	RTW89_CORE_RX_TYPE_CSI		= 11,
	RTW89_CORE_RX_TYPE_CQI		= 12,
};

struct rtw89_txwd_body {
	__le32 dword0;
	__le32 dword1;
	__le32 dword2;
	__le32 dword3;
	__le32 dword4;
	__le32 dword5;
} __packed;

struct rtw89_txwd_info {
	__le32 dword0;
	__le32 dword1;
	__le32 dword2;
	__le32 dword3;
	__le32 dword4;
	__le32 dword5;
} __packed;

struct rtw89_rx_desc_info {
	u16 pkt_size;
	u8 pkt_type;
	u8 drv_info_size;
	u8 shift;
	u8 wl_hd_iv_len;
	bool long_rxdesc;
	bool bb_sel;
	bool mac_info_valid;
	u16 data_rate;
	u8 bw;
	u32 free_run_cnt;
	u8 user_id;
	bool sr_en;
	u8 ppdu_cnt;
	u8 ppdu_type;
	bool icv_err;
	bool crc32_err;
	bool hw_dec;
	bool sw_dec;
	bool addr1_match;
	u8 frag;
	u16 seq;
	u8 rx_pl_id;
	bool addr_cam_valid;
	u8 addr_cam_id;
	u8 sec_cam_id;
	u8 mac_id;
};

struct rtw89_rxdesc_short {
	__le32 dword0;
	__le32 dword1;
	__le32 dword2;
	__le32 dword3;
} __packed;

struct rtw89_rxdesc_long {
	__le32 dword0;
	__le32 dword1;
	__le32 dword2;
	__le32 dword3;
	__le32 dword4;
	__le32 dword5;
	__le32 dword6;
	__le32 dword7;
} __packed;

struct rtw89_tx_desc_info {
	u16 pkt_size;
	u8 wp_offset;
	u8 qsel;
	u8 ch_dma;
	u8 hdr_llc_len;
	bool is_bmc;
	bool en_wd_info;
	bool wd_page;
	bool use_rate;
	bool dis_data_fb;
	u16 data_rate;
};

struct rtw89_core_tx_request {
	enum rtw89_core_tx_type tx_type;

	struct sk_buff *skb;
	struct ieee80211_vif *vif;
	struct ieee80211_sta *sta;
	struct rtw89_tx_desc_info desc_info;
};

struct rtw89_txq {
	struct list_head list;
};

struct rtw89_sta {
};

struct rtw89_vif {
};

struct rtw89_hci_ops {
	int (*tx)(struct rtw89_dev *rtwdev,
		  struct rtw89_core_tx_request *tx_req);
	void (*reset)(struct rtw89_dev *rtwdev);
	int (*start)(struct rtw89_dev *rtwdev);
	void (*stop)(struct rtw89_dev *rtwdev);

	u8 (*read8)(struct rtw89_dev *rtwdev, u32 addr);
	u16 (*read16)(struct rtw89_dev *rtwdev, u32 addr);
	u32 (*read32)(struct rtw89_dev *rtwdev, u32 addr);
	void (*write8)(struct rtw89_dev *rtwdev, u32 addr, u8 data);
	void (*write16)(struct rtw89_dev *rtwdev, u32 addr, u16 data);
	void (*write32)(struct rtw89_dev *rtwdev, u32 addr, u32 data);

	int (*mac_pre_init)(struct rtw89_dev *rtwdev);
	int (*mac_post_init)(struct rtw89_dev *rtwdev);

	int (*write_data_h2c)(struct rtw89_dev *rtwdev, struct sk_buff *skb);
};

struct rtw89_hci_info {
	const struct rtw89_hci_ops *ops;
	enum rtw89_hci_type type;
};

struct rtw89_chip_ops {
};

enum rtw89_dma_ch {
	RTW89_DMA_ACH0 = 0,
	RTW89_DMA_ACH1 = 1,
	RTW89_DMA_ACH2 = 2,
	RTW89_DMA_ACH3 = 3,
	RTW89_DMA_ACH4 = 4,
	RTW89_DMA_ACH5 = 5,
	RTW89_DMA_ACH6 = 6,
	RTW89_DMA_ACH7 = 7,
	RTW89_DMA_B0MG = 8,
	RTW89_DMA_B0HI = 9,
	RTW89_DMA_B1MG = 10,
	RTW89_DMA_B1HI = 11,
	RTW89_DMA_H2C = 12,
	RTW89_DMA_CH_NUM = 13
};

struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	const struct rtw89_chip_ops *ops;
	const char *fw_name;
	u32 fifo_size;
	u32 physical_size;
	u32 log_efuse_size;
	u32 sec_ctrl_efuse_size;
};

enum rtw89_qta_mode {
	RTW89_QTA_SCC,
	RTW89_QTA_DBCC,
	RTW89_QTA_SCC_WD128,
	RTW89_QTA_DBCC_WD128,
	RTW89_QTA_SCC_STF,
	RTW89_QTA_DBCC_STF,
	RTW89_QTA_SU_TP,
	RTW89_QTA_DLFW,
	RTW89_QTA_BCN_TEST,
	RTW89_QTA_LAMODE,

	/* keep last */
	RTW89_QTA_INVALID,
};

enum rtw89_hcifc_mode {
	RTW89_HCIFC_POH = 0,
	RTW89_HCIFC_STF = 1,
	RTW89_HCIFC_SDIO = 2,

	/* keep last */
	RTW89_HCIFC_MODE_INVALID,
};

struct rtw89_dle_info {
	enum rtw89_qta_mode qta_mode;
	u16 wde_pg_size;
	u16 ple_pg_size;
};

struct rtw89_hfc_ch_cfg {
	u16 min;
	u16 max;
#define grp_0 0
#define grp_1 1
#define grp_num 2
	u8 grp;
};

struct rtw89_hfc_ch_info {
	u16 aval;
	u16 used;
};

struct rtw89_hfc_pub_cfg {
	u16 grp0;
	u16 grp1;
	u16 pub_max;
	u16 wp_thrd;
};

struct rtw89_hfc_pub_info {
	u16 g0_used;
	u16 g1_used;
	u16 g0_aval;
	u16 g1_aval;
	u16 pub_aval;
	u16 wp_aval;
};

struct rtw89_hfc_prec_cfg {
	u16 ch011_prec;
	u16 h2c_prec;
	u16 wp_ch07_prec;
	u16 wp_ch811_prec;
	u8 ch011_full_cond;
	u8 h2c_full_cond;
	u8 wp_ch07_full_cond;
	u8 wp_ch811_full_cond;
};

struct rtw89_hfc_param {
	bool en;
	bool h2c_en;
	u8 mode;
	struct rtw89_hfc_ch_cfg *ch_cfg;
	struct rtw89_hfc_ch_info *ch_info;
	struct rtw89_hfc_pub_cfg *pub_cfg;
	struct rtw89_hfc_pub_info *pub_info;
	struct rtw89_hfc_prec_cfg *prec_cfg;
};

struct rtw89_mac_info {
	struct rtw89_dle_info dle_info;
	struct rtw89_hfc_param *hfc_param;
};

struct rtw89_fw_info {
	const struct firmware *firmware;
	struct rtw89_dev *rtwdev;
	struct completion completion;
	struct rtw89_fw_bin_info *bin_info;
	u16 ver;
	u8 sub_ver;
	u8 sub_idex;
	u16 build_year;
	u16 build_mon;
	u16 build_date;
	u16 build_hour;
	u16 build_min;
	u8 h2c_seq;
	u8 rec_seq;
};

struct rtw89_efuse {
	u32 physical_size;
	u32 logical_size;
};

struct rtw89_dev {
	struct ieee80211_hw *hw;
	struct device *dev;

	const struct rtw89_chip_info *chip;
	struct rtw89_mac_info mac;
	struct rtw89_fw_info fw;
	struct rtw89_efuse efuse;
	struct rtw89_hci_info hci;

	/* used to protect txqs list */
	spinlock_t txq_lock;
	struct list_head txqs;
	struct tasklet_struct txq_tasklet;

	/* HCI related data, keep last */
	u8 priv[0] __aligned(sizeof(void *));
};

static inline int rtw89_hci_tx(struct rtw89_dev *rtwdev,
			       struct rtw89_core_tx_request *tx_req)
{
	return rtwdev->hci.ops->tx(rtwdev, tx_req);
}

static inline void rtw89_hci_reset(struct rtw89_dev *rtwdev)
{
	rtwdev->hci.ops->reset(rtwdev);
}

static inline int rtw89_hci_start(struct rtw89_dev *rtwdev)
{
	return rtwdev->hci.ops->start(rtwdev);
}

static inline void rtw89_hci_stop(struct rtw89_dev *rtwdev)
{
	rtwdev->hci.ops->stop(rtwdev);
}

static inline int rtw89_hci_write_data_h2c(struct rtw89_dev *rtwdev,
					   struct sk_buff *skb)
{
	return rtwdev->hci.ops->write_data_h2c(rtwdev, skb);
}

static inline u8 rtw89_read8(struct rtw89_dev *rtwdev, u32 addr)
{
	return rtwdev->hci.ops->read8(rtwdev, addr);
}

static inline u16 rtw89_read16(struct rtw89_dev *rtwdev, u32 addr)
{
	return rtwdev->hci.ops->read16(rtwdev, addr);
}

static inline u32 rtw89_read32(struct rtw89_dev *rtwdev, u32 addr)
{
	return rtwdev->hci.ops->read32(rtwdev, addr);
}

static inline void rtw89_write8(struct rtw89_dev *rtwdev, u32 addr, u8 data)
{
	rtwdev->hci.ops->write8(rtwdev, addr, data);
}

static inline void rtw89_write16(struct rtw89_dev *rtwdev, u32 addr, u16 data)
{
	rtwdev->hci.ops->write16(rtwdev, addr, data);
}

static inline void rtw89_write32(struct rtw89_dev *rtwdev, u32 addr, u32 data)
{
	rtwdev->hci.ops->write32(rtwdev, addr, data);
}

static inline void
rtw89_write8_set(struct rtw89_dev *rtwdev, u32 addr, u8 bit)
{
	u8 val;

	val = rtw89_read8(rtwdev, addr);
	rtw89_write8(rtwdev, addr, val | bit);
}

static inline void
rtw89_write16_set(struct rtw89_dev *rtwdev, u32 addr, u16 bit)
{
	u16 val;

	val = rtw89_read16(rtwdev, addr);
	rtw89_write16(rtwdev, addr, val | bit);
}

static inline void
rtw89_write32_set(struct rtw89_dev *rtwdev, u32 addr, u32 bit)
{
	u32 val;

	val = rtw89_read32(rtwdev, addr);
	rtw89_write32(rtwdev, addr, val | bit);
}

static inline void
rtw89_write8_clr(struct rtw89_dev *rtwdev, u32 addr, u8 bit)
{
	u8 val;

	val = rtw89_read8(rtwdev, addr);
	rtw89_write8(rtwdev, addr, val & ~bit);
}

static inline void
rtw89_write16_clr(struct rtw89_dev *rtwdev, u32 addr, u16 bit)
{
	u16 val;

	val = rtw89_read16(rtwdev, addr);
	rtw89_write16(rtwdev, addr, val & ~bit);
}

static inline void
rtw89_write32_clr(struct rtw89_dev *rtwdev, u32 addr, u32 bit)
{
	u32 val;

	val = rtw89_read32(rtwdev, addr);
	rtw89_write32(rtwdev, addr, val & ~bit);
}

static inline u32
rtw89_read32_mask(struct rtw89_dev *rtwdev, u32 addr, u32 mask)
{
	u32 shift = __ffs(mask);
	u32 orig;
	u32 ret;

	orig = rtw89_read32(rtwdev, addr);
	ret = (orig & mask) >> shift;

	return ret;
}

static inline u16
rtw89_read16_mask(struct rtw89_dev *rtwdev, u32 addr, u32 mask)
{
	u32 shift = __ffs(mask);
	u32 orig;
	u32 ret;

	orig = rtw89_read16(rtwdev, addr);
	ret = (orig & mask) >> shift;

	return ret;
}

static inline u8
rtw89_read8_mask(struct rtw89_dev *rtwdev, u32 addr, u32 mask)
{
	u32 shift = __ffs(mask);
	u32 orig;
	u32 ret;

	orig = rtw89_read8(rtwdev, addr);
	ret = (orig & mask) >> shift;

	return ret;
}

static inline void
rtw89_write32_mask(struct rtw89_dev *rtwdev, u32 addr, u32 mask, u32 data)
{
	u32 shift = __ffs(mask);
	u32 orig;
	u32 set;

	WARN(addr & 0x3, "should be 4-byte aligned, addr = 0x%08x\n", addr);

	orig = rtw89_read32(rtwdev, addr);
	set = (orig & ~mask) | ((data << shift) & mask);
	rtw89_write32(rtwdev, addr, set);
}

static inline void
rtw89_write16_mask(struct rtw89_dev *rtwdev, u32 addr, u32 mask, u16 data)
{
	u32 shift;
	u16 orig, set;

	mask &= 0xffff;
	shift = __ffs(mask);

	orig = rtw89_read16(rtwdev, addr);
	set = (orig & ~mask) | ((data << shift) & mask);
	rtw89_write16(rtwdev, addr, set);
}

static inline void
rtw89_write8_mask(struct rtw89_dev *rtwdev, u32 addr, u32 mask, u8 data)
{
	u32 shift;
	u8 orig, set;

	mask &= 0xff;
	shift = __ffs(mask);

	orig = rtw89_read8(rtwdev, addr);
	set = (orig & ~mask) | ((data << shift) & mask);
	rtw89_write8(rtwdev, addr, set);
}
int rtw89_core_tx(struct rtw89_dev *rtwdev,
		  struct ieee80211_vif *vif,
		  struct ieee80211_sta *sta,
		  struct sk_buff *skb);
void rtw89_core_fill_txdesc(struct rtw89_dev *rtwdev,
			    struct rtw89_tx_desc_info *desc_info,
			    void *txdesc);
void rtw89_core_rx_process_report(struct rtw89_dev *rtwdev,
				  struct sk_buff *skb);
void rtw89_core_query_rxdesc(struct rtw89_dev *rtwdev,
			     struct rtw89_rx_desc_info *desc_info,
			     u8 *data);
void rtw89_core_update_rx_status(struct rtw89_dev *rtwdev,
				 struct rtw89_rx_desc_info *desc_info,
				 struct ieee80211_rx_status *rx_status);
int rtw89_core_power_on(struct rtw89_dev *rtwdev);
int rtw89_core_register(struct rtw89_dev *rtwdev);
void rtw89_core_unregister(struct rtw89_dev *rtwdev);

#endif
