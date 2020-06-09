// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include <linux/bitfield.h>

#include "core.h"
#include "txrx.h"
#include "debug.h"
#include "mac.h"
#include "fw.h"

static struct ieee80211_channel rtw89_channels_2ghz[] = {
	{ .center_freq = 2412, .hw_value = 1, },
	{ .center_freq = 2417, .hw_value = 2, },
	{ .center_freq = 2422, .hw_value = 3, },
	{ .center_freq = 2427, .hw_value = 4, },
	{ .center_freq = 2432, .hw_value = 5, },
	{ .center_freq = 2437, .hw_value = 6, },
	{ .center_freq = 2442, .hw_value = 7, },
	{ .center_freq = 2447, .hw_value = 8, },
	{ .center_freq = 2452, .hw_value = 9, },
	{ .center_freq = 2457, .hw_value = 10, },
	{ .center_freq = 2462, .hw_value = 11, },
	{ .center_freq = 2467, .hw_value = 12, },
	{ .center_freq = 2472, .hw_value = 13, },
	{ .center_freq = 2484, .hw_value = 14, },
};

static struct ieee80211_channel rtw89_channels_5ghz[] = {
	{.center_freq = 5180, .hw_value = 36,},
	{.center_freq = 5200, .hw_value = 40,},
	{.center_freq = 5220, .hw_value = 44,},
	{.center_freq = 5240, .hw_value = 48,},
	{.center_freq = 5260, .hw_value = 52,},
	{.center_freq = 5280, .hw_value = 56,},
	{.center_freq = 5300, .hw_value = 60,},
	{.center_freq = 5320, .hw_value = 64,},
	{.center_freq = 5500, .hw_value = 100,},
	{.center_freq = 5520, .hw_value = 104,},
	{.center_freq = 5540, .hw_value = 108,},
	{.center_freq = 5560, .hw_value = 112,},
	{.center_freq = 5580, .hw_value = 116,},
	{.center_freq = 5600, .hw_value = 120,},
	{.center_freq = 5620, .hw_value = 124,},
	{.center_freq = 5640, .hw_value = 128,},
	{.center_freq = 5660, .hw_value = 132,},
	{.center_freq = 5680, .hw_value = 136,},
	{.center_freq = 5700, .hw_value = 140,},
	{.center_freq = 5745, .hw_value = 149,},
	{.center_freq = 5765, .hw_value = 153,},
	{.center_freq = 5785, .hw_value = 157,},
	{.center_freq = 5805, .hw_value = 161,},
	{.center_freq = 5825, .hw_value = 165,
	 .flags = IEEE80211_CHAN_NO_HT40MINUS},
};

static struct ieee80211_rate rtw89_bitrates[] = {
	{ .bitrate = 10,  .hw_value = 0x00, },
	{ .bitrate = 20,  .hw_value = 0x01, },
	{ .bitrate = 55,  .hw_value = 0x02, },
	{ .bitrate = 110, .hw_value = 0x03, },
	{ .bitrate = 60,  .hw_value = 0x04, },
	{ .bitrate = 90,  .hw_value = 0x05, },
	{ .bitrate = 120, .hw_value = 0x06, },
	{ .bitrate = 180, .hw_value = 0x07, },
	{ .bitrate = 240, .hw_value = 0x08, },
	{ .bitrate = 360, .hw_value = 0x09, },
	{ .bitrate = 480, .hw_value = 0x0a, },
	{ .bitrate = 540, .hw_value = 0x0b, },
};

static struct ieee80211_supported_band rtw89_sband_2ghz = {
	.band		= NL80211_BAND_2GHZ,
	.channels	= rtw89_channels_2ghz,
	.n_channels	= ARRAY_SIZE(rtw89_channels_2ghz),
	.bitrates	= rtw89_bitrates,
	.n_bitrates	= ARRAY_SIZE(rtw89_bitrates),
	.ht_cap		= {0},
	.vht_cap	= {0},
};

static struct ieee80211_supported_band rtw89_sband_5ghz = {
	.band		= NL80211_BAND_5GHZ,
	.channels	= rtw89_channels_5ghz,
	.n_channels	= ARRAY_SIZE(rtw89_channels_5ghz),

	/* 5G has no CCK rates, 1M/2M/5.5M/11M */
	.bitrates	= rtw89_bitrates + 4,
	.n_bitrates	= ARRAY_SIZE(rtw89_bitrates) - 4,
	.ht_cap		= {0},
	.vht_cap	= {0},
};

static enum rtw89_core_tx_type
rtw89_core_get_tx_type(struct rtw89_dev *rtwdev,
		       struct sk_buff *skb)
{
	struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;

	if (ieee80211_is_mgmt(fc) || ieee80211_is_nullfunc(fc))
		return RTW89_CORE_TX_TYPE_MGMT;

	return RTW89_CORE_TX_TYPE_DATA;
}

static void
rtw89_core_tx_update_mgmt_info(struct rtw89_dev *rtwdev,
			       struct rtw89_core_tx_request *tx_req)
{
	struct rtw89_tx_desc_info *desc_info = &tx_req->desc_info;

	desc_info->wp_offset = 0;
	desc_info->ch_dma = RTW89_DMA_B0MG; /* TODO: check B0/B1 */
	desc_info->qsel = 0x12;
	desc_info->hdr_llc_len = 24;
}

static void
rtw89_core_tx_update_data_info(struct rtw89_dev *rtwdev,
			       struct rtw89_core_tx_request *tx_req)
{
	struct rtw89_tx_desc_info *desc_info = &tx_req->desc_info;

	desc_info->wp_offset = 56;
	desc_info->ch_dma = RTW89_DMA_ACH0; /* TODO: mapping TID ? */
	desc_info->qsel = 0; /* TODO: qsel for WMM data frames */
	desc_info->hdr_llc_len = 26; /* TODO QoS ? */
}

static void
rtw89_core_tx_update_desc_info(struct rtw89_dev *rtwdev,
			       struct rtw89_core_tx_request *tx_req)
{
	struct rtw89_tx_desc_info *desc_info = &tx_req->desc_info;
	struct sk_buff *skb = tx_req->skb;
	struct ieee80211_hdr *hdr = (void *)skb->data;
	enum rtw89_core_tx_type tx_type;
	bool is_bmc;

	tx_type = rtw89_core_get_tx_type(rtwdev, skb);
	is_bmc = (is_broadcast_ether_addr(hdr->addr1) ||
		  is_multicast_ether_addr(hdr->addr1));

	tx_req->tx_type = tx_type;
	desc_info->pkt_size = skb->len;
	desc_info->is_bmc = is_bmc;
	desc_info->wd_page = true;

	switch (tx_type) {
	case RTW89_CORE_TX_TYPE_MGMT:
		rtw89_core_tx_update_mgmt_info(rtwdev, tx_req);
		break;
	case RTW89_CORE_TX_TYPE_DATA:
		rtw89_core_tx_update_data_info(rtwdev, tx_req);
		break;
	case RTW89_CORE_TX_TYPE_FWCMD:
		break;
	}
}

int rtw89_core_tx(struct rtw89_dev *rtwdev,
		  struct ieee80211_vif *vif,
		  struct ieee80211_sta *sta,
		  struct sk_buff *skb)
{
	struct rtw89_core_tx_request tx_req = {0};
	int ret;

	tx_req.skb = skb;
	tx_req.sta = sta;
	tx_req.vif = vif;

	rtw89_core_tx_update_desc_info(rtwdev, &tx_req);
	ret = rtw89_hci_tx(rtwdev, &tx_req);
	if (ret) {
		rtw89_err(rtwdev, "failed to transmit skb to HCI\n");
		return ret;
	}

	return 0;
}

void rtw89_core_fill_txdesc(struct rtw89_dev *rtwdev,
			    struct rtw89_tx_desc_info *desc_info,
			    void *txdesc)
{
	struct rtw89_txwd_body *txwd_body = txdesc;
	struct rtw89_txwd_info *txwd_info;
	u32 dword;

	dword = FIELD_PREP(RTW89_TXWD_WP_OFFSET, desc_info->wp_offset) |
		FIELD_PREP(RTW89_TXWD_WD_INFO_EN, desc_info->en_wd_info) |
		FIELD_PREP(RTW89_TXWD_HDR_LLC_LEN, desc_info->hdr_llc_len) |
		FIELD_PREP(RTW89_TXWD_WD_PAGE, desc_info->wd_page) |
		FIELD_PREP(RTW89_TXWD_CHANNEL_DMA, desc_info->ch_dma);
	txwd_body->dword0 = cpu_to_le32(dword);

	dword = FIELD_PREP(RTW89_TXWD_TXPKT_SIZE, desc_info->pkt_size) |
		FIELD_PREP(RTW89_TXWD_QSEL, desc_info->qsel);
	txwd_body->dword2 = cpu_to_le32(dword);

	if (!desc_info->en_wd_info)
		return;

	txwd_info = txdesc + sizeof(*txwd_body);
}
EXPORT_SYMBOL(rtw89_core_fill_txdesc);

void rtw89_core_rx_process_report(struct rtw89_dev *rtwdev,
				  struct sk_buff *skb)
{
}
EXPORT_SYMBOL(rtw89_core_rx_process_report);

void rtw89_core_query_rxdesc(struct rtw89_dev *rtwdev,
			     struct rtw89_rx_desc_info *desc_info,
			     u8 *data)
{
	struct rtw89_rxdesc_short *rxd_s;
	struct rtw89_rxdesc_long *rxd_l;

	rxd_s = (struct rtw89_rxdesc_short *)data;
	desc_info->pkt_size = RTW89_GET_RXD_PKT_SIZE(rxd_s);
	desc_info->drv_info_size = RTW89_GET_RXD_DRV_INFO_SIZE(rxd_s);
	desc_info->long_rxdesc = RTW89_GET_RXD_LONG_RXD(rxd_s);
	desc_info->pkt_type = RTW89_GET_RXD_RPKT_TYPE(rxd_s);
	desc_info->mac_info_valid = RTW89_GET_RXD_MAC_INFO_VALID(rxd_s);
	desc_info->bw = RTW89_GET_RXD_BW(rxd_s);
	desc_info->data_rate = RTW89_GET_RXD_DATA_RATE(rxd_s);
	desc_info->user_id = RTW89_GET_RXD_USER_ID(rxd_s);
	desc_info->sr_en = RTW89_GET_RXD_SR_EN(rxd_s);
	desc_info->ppdu_cnt = RTW89_GET_RXD_PPDU_CNT(rxd_s);
	desc_info->ppdu_type = RTW89_GET_RXD_PPDU_TYPE(rxd_s);
	desc_info->free_run_cnt = RTW89_GET_RXD_FREE_RUN_CNT(rxd_s);
	desc_info->icv_err = RTW89_GET_RXD_ICV_ERR(rxd_s);
	desc_info->crc32_err = RTW89_GET_RXD_CRC32_ERR(rxd_s);
	desc_info->hw_dec = RTW89_GET_RXD_HW_DEC(rxd_s);
	desc_info->sw_dec = RTW89_GET_RXD_SW_DEC(rxd_s);
	desc_info->addr1_match = RTW89_GET_RXD_A1_MATCH(rxd_s);

	if (!desc_info->long_rxdesc)
		return;

	rxd_l = (struct rtw89_rxdesc_long *)data;
	desc_info->addr_cam_valid = RTW89_GET_RXD_ADDR_CAM_VLD(rxd_l);
	desc_info->addr_cam_id = RTW89_GET_RXD_ADDR_CAM_ID(rxd_l);
	desc_info->sec_cam_id = RTW89_GET_RXD_SEC_CAM_ID(rxd_l);
	desc_info->mac_id = RTW89_GET_RXD_MAC_ID(rxd_l);
	desc_info->rx_pl_id = RTW89_GET_RXD_RX_PL_ID(rxd_l);
}
EXPORT_SYMBOL(rtw89_core_query_rxdesc);

void rtw89_core_update_rx_status(struct rtw89_dev *rtwdev,
				 struct rtw89_rx_desc_info *desc_info,
				 struct ieee80211_rx_status *rx_status)
{
}
EXPORT_SYMBOL(rtw89_core_update_rx_status);

static void rtw89_core_txq_tasklet(unsigned long data)
{
	struct rtw89_dev *rtwdev = (void *)data;
	struct rtw89_txq *rtwtxq, *tmp;

	spin_lock_bh(&rtwdev->txq_lock);
	list_for_each_entry_safe(rtwtxq, tmp, &rtwdev->txqs, list) {
		list_del_init(&rtwtxq->list);
	}
	spin_unlock_bh(&rtwdev->txq_lock);
}

int rtw89_core_power_on(struct rtw89_dev *rtwdev)
{
	int ret;

	ret = rtw89_mac_pwr_on(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to start power sequence\n");
		goto err;
	}

	return 0;

err:
	return ret;
}

static int rtw89_core_set_supported_band(struct rtw89_dev *rtwdev)
{
	struct ieee80211_hw *hw = rtwdev->hw;
	struct ieee80211_supported_band *sband_2ghz = NULL, *sband_5ghz = NULL;
	u32 size = sizeof(struct ieee80211_supported_band);

	sband_2ghz = kmemdup(&rtw89_sband_2ghz, size, GFP_KERNEL);
	if (!sband_2ghz)
		goto err;
	hw->wiphy->bands[NL80211_BAND_2GHZ] = sband_2ghz;

	sband_5ghz = kmemdup(&rtw89_sband_5ghz, size, GFP_KERNEL);
	if (!sband_5ghz)
		goto err;
	hw->wiphy->bands[NL80211_BAND_5GHZ] = sband_5ghz;

	return 0;

err:
	hw->wiphy->bands[NL80211_BAND_2GHZ] = NULL;
	hw->wiphy->bands[NL80211_BAND_5GHZ] = NULL;
	kfree(sband_2ghz);
	kfree(sband_5ghz);
	return -ENOMEM;
}

static void rtw89_core_clr_supported_band(struct rtw89_dev *rtwdev)
{
	struct ieee80211_hw *hw = rtwdev->hw;

	kfree(hw->wiphy->bands[NL80211_BAND_2GHZ]);
	kfree(hw->wiphy->bands[NL80211_BAND_5GHZ]);
	hw->wiphy->bands[NL80211_BAND_2GHZ] = NULL;
	hw->wiphy->bands[NL80211_BAND_5GHZ] = NULL;
}

static int rtw89_core_init(struct rtw89_dev *rtwdev)
{
	unsigned long data = (unsigned long)rtwdev;
	int ret;

	INIT_LIST_HEAD(&rtwdev->txqs);
	tasklet_init(&rtwdev->txq_tasklet, rtw89_core_txq_tasklet, data);
	spin_lock_init(&rtwdev->txq_lock);

	ret = rtw89_fw_request(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to request firmware\n");
		return ret;
	}

	ret = rtw89_core_set_supported_band(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to set supported band\n");
		return ret;
	}

	return 0;
}

static void rtw89_core_deinit(struct rtw89_dev *rtwdev)
{
	rtw89_core_clr_supported_band(rtwdev);
	tasklet_kill(&rtwdev->txq_tasklet);
	if (!rtwdev->fw.bin_info)
		kfree(rtwdev->fw.bin_info);
}

static int rtw89_core_register_hw(struct rtw89_dev *rtwdev)
{
	struct ieee80211_hw *hw = rtwdev->hw;
	u8 temp_addr[ETH_ALEN] = {0x00, 0xe0, 0x4c, 0x88, 0x52, 0xae};
	int ret;

	hw->vif_data_size = sizeof(struct rtw89_vif);
	hw->sta_data_size = sizeof(struct rtw89_sta);
	hw->txq_data_size = sizeof(struct rtw89_txq);

	SET_IEEE80211_PERM_ADDR(hw, temp_addr);

	ieee80211_hw_set(hw, SIGNAL_DBM);
	ieee80211_hw_set(hw, RX_INCLUDES_FCS);

	hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);

	ret = ieee80211_register_hw(hw);
	if (ret) {
		rtw89_err(rtwdev, "failed to register hw\n");
		goto err;
	}

	return 0;

err:
	return ret;
}

static void rtw89_core_unregister_hw(struct rtw89_dev *rtwdev)
{
	struct ieee80211_hw *hw = rtwdev->hw;

	ieee80211_unregister_hw(hw);
}

int rtw89_core_register(struct rtw89_dev *rtwdev)
{
	int ret;

	ret = rtw89_core_init(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to initialise core\n");
		goto err;
	}

	ret = rtw89_core_register_hw(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to register core hw\n");
		goto err_core_deinit;
	}

	rtw89_debugfs_init(rtwdev);

	return 0;

err_core_deinit:
	rtw89_core_deinit(rtwdev);
err:
	return ret;
}
EXPORT_SYMBOL(rtw89_core_register);

void rtw89_core_unregister(struct rtw89_dev *rtwdev)
{
	rtw89_core_deinit(rtwdev);
	rtw89_core_unregister_hw(rtwdev);
}
EXPORT_SYMBOL(rtw89_core_unregister);

MODULE_AUTHOR("Realtek Corporation");
MODULE_DESCRIPTION("Realtek 802.11ax wireless core module");
MODULE_LICENSE("Dual BSD/GPL");
