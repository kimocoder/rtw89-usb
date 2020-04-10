// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include "core.h"
#include "debug.h"
#include "mac.h"

static void rtw89_ops_tx(struct ieee80211_hw *hw,
			 struct ieee80211_tx_control *control,
			 struct sk_buff *skb)
{
	struct rtw89_dev *rtwdev = hw->priv;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_vif *vif = info->control.vif;
	struct ieee80211_sta *sta = control->sta;
	int ret;

	ret = rtw89_core_tx(rtwdev, vif, sta, skb);
	if (ret) {
		rtw89_err(rtwdev, "failed to transmit skb: %d\n", ret);
		ieee80211_free_txskb(hw, skb);
	}
}

static void rtw89_ops_wake_tx_queue(struct ieee80211_hw *hw,
				    struct ieee80211_txq *txq)
{
	struct rtw89_dev *rtwdev = hw->priv;
	struct rtw89_txq *rtwtxq = (struct rtw89_txq *)txq->drv_priv;

	spin_lock_bh(&rtwdev->txq_lock);
	if (list_empty(&rtwtxq->list))
		list_add_tail(&rtwtxq->list, &rtwdev->txqs);
	spin_unlock_bh(&rtwdev->txq_lock);

	tasklet_schedule(&rtwdev->txq_tasklet);
}

static int rtw89_ops_start(struct ieee80211_hw *hw)
{
	struct rtw89_dev *rtwdev = hw->priv;
	int ret;

	rtwdev->mac.dle_info.qta_mode = RTW89_QTA_SCC_WD128;
	ret = rtw89_mac_init(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "mac init fail, ret:%d\n", ret);
		return ret;
	}

	return 0;
}

static void rtw89_ops_stop(struct ieee80211_hw *hw)
{
}

static int rtw89_ops_config(struct ieee80211_hw *hw, u32 changed)
{
	return 0;
}

static int rtw89_ops_add_interface(struct ieee80211_hw *hw,
				   struct ieee80211_vif *vif)
{
	return 0;
}

static void rtw89_ops_remove_interface(struct ieee80211_hw *hw,
				       struct ieee80211_vif *vif)
{
}

static void rtw89_ops_configure_filter(struct ieee80211_hw *hw,
				       unsigned int changed_flags,
				       unsigned int *new_flags,
				       u64 multicast)
{
	*new_flags = 1;
}

static void rtw89_ops_bss_info_changed(struct ieee80211_hw *hw,
				       struct ieee80211_vif *vif,
				       struct ieee80211_bss_conf *conf,
				       u32 changed)
{
}

static int rtw89_ops_sta_state(struct ieee80211_hw *hw,
			       struct ieee80211_vif *vif,
			       struct ieee80211_sta *sta,
			       enum ieee80211_sta_state old_state,
			       enum ieee80211_sta_state new_state)
{
	return 0;
}

static int rtw89_ops_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
			     struct ieee80211_vif *vif,
			     struct ieee80211_sta *sta,
			     struct ieee80211_key_conf *key)
{
	return 0;
}

const struct ieee80211_ops rtw89_ops = {
	.tx			= rtw89_ops_tx,
	.wake_tx_queue		= rtw89_ops_wake_tx_queue,
	.start			= rtw89_ops_start,
	.stop			= rtw89_ops_stop,
	.config			= rtw89_ops_config,
	.add_interface		= rtw89_ops_add_interface,
	.remove_interface	= rtw89_ops_remove_interface,
	.configure_filter	= rtw89_ops_configure_filter,
	.bss_info_changed	= rtw89_ops_bss_info_changed,
	.sta_state		= rtw89_ops_sta_state,
	.set_key		= rtw89_ops_set_key,
};
EXPORT_SYMBOL(rtw89_ops);
