// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2020  Realtek Corporation
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/bitfield.h>
#include <linux/interrupt.h>

#include "core.h"
#include "pci.h"
#include "reg.h"
#include "debug.h"

static int rtw89_pci_get_txch_addrs(enum rtw89_pci_tx_channel txch,
				    u32 *addr_num,
				    u32 *addr_idx,
				    u32 *addr_desa)
{
#define case_TXCHADDRS(txch) \
	case RTW89_PCI_TXCH_##txch: \
		*addr_num = R_AX_##txch##_TXBD_NUM; \
		*addr_idx = R_AX_##txch##_TXBD_IDX; \
		*addr_desa = R_AX_##txch##_TXBD_DESA_L; \
		break

	switch (txch) {
	case_TXCHADDRS(ACH0);
	case_TXCHADDRS(ACH1);
	case_TXCHADDRS(ACH2);
	case_TXCHADDRS(ACH3);
	case_TXCHADDRS(ACH4);
	case_TXCHADDRS(ACH5);
	case_TXCHADDRS(ACH6);
	case_TXCHADDRS(ACH7);
	case_TXCHADDRS(CH8);
	case_TXCHADDRS(CH9);
	case_TXCHADDRS(CH10);
	case_TXCHADDRS(CH11);
	case_TXCHADDRS(CH12);
	default:
		return -EINVAL;
	}

	return 0;
#undef case_TXCHADDRS
}

static int rtw89_pci_get_rxch_addrs(enum rtw89_pci_rx_channel rxch,
				    u32 *addr_num,
				    u32 *addr_idx,
				    u32 *addr_desa)
{
#define case_RXCHADDRS(rxch) \
	case RTW89_PCI_RXCH_##rxch: \
		*addr_num = R_AX_##rxch##_RXBD_NUM; \
		*addr_idx = R_AX_##rxch##_RXBD_IDX; \
		*addr_desa = R_AX_##rxch##_RXBD_DESA_L; \
		break

	switch (rxch) {
	case_RXCHADDRS(RXQ);
	case_RXCHADDRS(RPQ);
	default:
		return -EINVAL;
	}

	return 0;
#undef case_RXCHADDRS
}

static u8 rtw89_pci_tx_queue_select(struct rtw89_dev *rtwdev,
				    enum rtw89_core_tx_type tx_type,
				    struct sk_buff *skb)
{
	u8 qsel = 0;

	switch (tx_type) {
	case RTW89_CORE_TX_TYPE_MGMT:
		qsel = RTW89_PCI_TXCH_CH8;
		break;
	case RTW89_CORE_TX_TYPE_FWCMD:
		qsel = RTW89_PCI_TXCH_CH12;
		break;
	default:
		qsel = skb->priority;
		break;
	}

	return qsel;
}

static u32 rtw89_pci_get_avail_txbd_num(struct rtw89_pci_tx_ring *ring)
{
	struct rtw89_pci_dma_ring *bd_ring = &ring->bd_ring;

	/* reserved 1 desc check ring is full or not */
	if (bd_ring->rp > bd_ring->wp)
		return bd_ring->rp - bd_ring->wp - 1;

	return bd_ring->len - (bd_ring->wp - bd_ring->rp) - 1;
}

static void rtw89_pci_tx_kick_off(struct rtw89_dev *rtwdev,
				  struct rtw89_pci_tx_ring *tx_ring,
				  int n_txbd)
{
	struct rtw89_pci_dma_ring *bd_ring = &tx_ring->bd_ring;
	u32 host_idx, len, addr;

	addr = bd_ring->addr_idx;
	len = bd_ring->len;
	host_idx = bd_ring->wp + n_txbd;
	host_idx = host_idx < len ? host_idx : host_idx - len;
	rtw89_write16(rtwdev, addr, host_idx);

	bd_ring->wp = host_idx;
}

static int rtw89_pci_txwd_submit(struct rtw89_dev *rtwdev,
				 struct rtw89_pci_tx_wd *txwd,
				 struct rtw89_core_tx_request *tx_req)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	struct rtw89_tx_desc_info *desc_info = &tx_req->desc_info;
	struct rtw89_txwd_body *txwd_body;
	struct rtw89_txwd_info *txwd_info;
	struct rtw89_pci_tx_wp_info *txwp_info;
	struct rtw89_pci_tx_addr_info_32 *txaddr_info;
	struct pci_dev *pdev = rtwpci->pdev;
	struct sk_buff *skb = tx_req->skb;
	struct rtw89_pci_tx_data *tx_data = RTW89_PCI_TX_SKB_CB(skb);
	bool en_wd_info = desc_info->en_wd_info;
	u32 txwd_len;
	u32 txwp_len;
	dma_addr_t dma;
	int ret;

	rtw89_core_fill_txdesc(rtwdev, desc_info, txwd->vaddr);

	dma = pci_map_single(pdev, skb->data, skb->len, PCI_DMA_TODEVICE);
	if (pci_dma_mapping_error(pdev, dma)) {
		rtw89_err(rtwdev, "failed to map skb dma data\n");
		ret = -EBUSY;
		goto err;
	}

	tx_data->dma = dma;

	txwp_len = sizeof(*txwp_info);
	txwd_len = sizeof(*txwd_body);
	txwd_len += en_wd_info ? sizeof(txwd_info) : 0;

	txwp_info = txwd->vaddr + txwd_len;
	txwp_info->seq0 = cpu_to_le16(txwd->seq | RTW89_PCI_TXWP_VALID);
	txwp_info->seq1 = 0;
	txwp_info->seq2 = 0;
	txwp_info->seq3 = 0;

	txaddr_info = txwd->vaddr + txwd_len + txwp_len;
	txaddr_info->length = cpu_to_le16(skb->len);
	txaddr_info->option = cpu_to_le16(RTW89_PCI_ADDR_LS | 1);
	txaddr_info->dma = cpu_to_le32(dma);

	skb_queue_tail(&txwd->queue, skb);

	return 0;

err:
	return ret;
}

static int rtw89_pci_txbd_submit(struct rtw89_dev *rtwdev,
				 struct rtw89_pci_tx_ring *tx_ring,
				 struct rtw89_pci_tx_bd_32 *txbd,
				 struct rtw89_pci_tx_wd *txwd,
				 struct rtw89_core_tx_request *tx_req)
{
	int ret;

	ret = rtw89_pci_txwd_submit(rtwdev, txwd, tx_req);
	if (ret) {
		rtw89_err(rtwdev, "failed to submit TXWD %d\n", txwd->seq);
		goto err;
	}

	list_add_tail(&txwd->list, &tx_ring->busy_pages);

	txbd->option = cpu_to_le16(RTW89_PCI_TXBD_OPTION_LS);
	txbd->length = cpu_to_le16(txwd->len);
	txbd->dma = cpu_to_le16(txwd->paddr);

	/* kick off TX engine */
	rtw89_pci_tx_kick_off(rtwdev, tx_ring, 1);

	return 0;

err:
	return ret;
}

static int rtw89_pci_tx(struct rtw89_dev *rtwdev,
			struct rtw89_core_tx_request *tx_req,
			u8 qsel)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	struct rtw89_pci_tx_ring *tx_ring;
	struct rtw89_pci_tx_bd_32 *txbd;
	struct rtw89_pci_tx_wd *txwd;
	u32 n_avail_txbd;
	int ret = 0;

	tx_ring = &rtwpci->tx_rings[qsel];

	spin_lock_bh(&rtwpci->trx_lock);

	n_avail_txbd = rtw89_pci_get_avail_txbd_num(tx_ring);
	if (n_avail_txbd == 0) {
		rtw89_err(rtwdev, "no available TXBD\n");
		ret = -ENOSPC;
		goto err_unlock;
	}

	txbd = rtw89_pci_get_next_txbd(tx_ring);
	txwd = rtw89_pci_dequeue_txwd(tx_ring);
	if (!txwd) {
		rtw89_err(rtwdev, "no available TXWD\n");
		ret = -ENOSPC;
		goto err_unlock;
	}

	ret = rtw89_pci_txbd_submit(rtwdev, tx_ring, txbd, txwd, tx_req);
	if (ret) {
		rtw89_err(rtwdev, "failed to submit TXBD\n");
		goto err_enqueue_wd;
	}

	spin_unlock_bh(&rtwpci->trx_lock);
	return 0;

err_enqueue_wd:
	rtw89_pci_enqueue_txwd(tx_ring, txwd);
err_unlock:
	spin_unlock_bh(&rtwpci->trx_lock);
	return ret;
}

static int rtw89_pci_ops_tx(struct rtw89_dev *rtwdev,
			    struct rtw89_core_tx_request *tx_req)
{
	struct rtw89_tx_desc_info *desc_info = &tx_req->desc_info;
	u8 qsel;
	int ret;

	qsel = rtw89_pci_tx_queue_select(rtwdev, tx_req->tx_type, tx_req->skb);

	desc_info->qsel = qsel;
	desc_info->wp_offset = 56; /* FIXME: we will know why 56 someday */

	ret = rtw89_pci_tx(rtwdev, tx_req, qsel);
	if (ret) {
		rtw89_err(rtwdev, "failed to TX Queue %d\n", qsel);
		return ret;
	}

	return 0;
}

static void rtw89_pci_reset_trx_rings(struct rtw89_dev *rtwdev)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	struct rtw89_pci_tx_ring *tx_ring;
	struct rtw89_pci_rx_ring *rx_ring;
	struct rtw89_pci_dma_ring *bd_ring;
	u32 addr_num;
	u32 addr_desa;
	int i;

	for (i = 0; i < RTW89_PCI_TXCH_NUM; i++) {
		tx_ring = &rtwpci->tx_rings[i];
		bd_ring = &tx_ring->bd_ring;
		addr_num = bd_ring->addr_num;
		addr_desa = bd_ring->addr_desa;

		rtw89_write32(rtwdev, addr_num, bd_ring->len);
		rtw89_write32(rtwdev, addr_desa, bd_ring->dma);
	}

	for (i = 0; i < RTW89_PCI_RXCH_NUM; i++) {
		rx_ring = &rtwpci->rx_rings[i];
		bd_ring = &rx_ring->bd_ring;
		addr_num = bd_ring->addr_num;
		addr_desa = bd_ring->addr_desa;

		rtw89_write32(rtwdev, addr_num, bd_ring->len);
		rtw89_write32(rtwdev, addr_desa, bd_ring->dma);
	}

	rtw89_write16(rtwdev, R_AX_TXBD_RWPTR_CLR1, B_AX_TXBD_CLR1_ALL);
	rtw89_write16(rtwdev, R_AX_TXBD_RWPTR_CLR2, B_AX_TXBD_CLR2_ALL);
	rtw89_write16(rtwdev, R_AX_RXBD_RWPTR_CLR, B_AX_RXBD_CLR_ALL);
}

static void rtw89_pci_ops_reset(struct rtw89_dev *rtwdev)
{
	rtw89_pci_reset_trx_rings(rtwdev);
}

static u8 rtw89_pci_ops_read8(struct rtw89_dev *rtwdev, u32 addr)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;

	return readb(rtwpci->mmap + addr);
}

static u16 rtw89_pci_ops_read16(struct rtw89_dev *rtwdev, u32 addr)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;

	return readw(rtwpci->mmap + addr);
}

static u32 rtw89_pci_ops_read32(struct rtw89_dev *rtwdev, u32 addr)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;

	return readl(rtwpci->mmap + addr);
}

static void rtw89_pci_ops_write8(struct rtw89_dev *rtwdev, u32 addr, u8 data)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;

	writeb(data, rtwpci->mmap + addr);
}

static void rtw89_pci_ops_write16(struct rtw89_dev *rtwdev, u32 addr, u16 data)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;

	writew(data, rtwpci->mmap + addr);
}

static void rtw89_pci_ops_write32(struct rtw89_dev *rtwdev, u32 addr, u32 data)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;

	writel(data, rtwpci->mmap + addr);
}

static void rtw89_pci_ctrl_dma_all(struct rtw89_dev *rtwdev, bool enable)
{
	if (enable) {
		rtw89_write32_set(rtwdev, R_AX_PCIE_INIT_CFG1,
				  B_AX_TXHCI_EN | B_AX_RXHCI_EN);
		rtw89_write32_clr(rtwdev, R_AX_PCIE_DMA_STOP1,
				  B_AX_STOP_PCIEIO);
	} else {
		rtw89_write32_set(rtwdev, R_AX_PCIE_DMA_STOP1,
				  B_AX_STOP_PCIEIO);
		rtw89_write32_clr(rtwdev, R_AX_PCIE_INIT_CFG1,
				  B_AX_TXHCI_EN | B_AX_RXHCI_EN);
	}
}

static void rtw89_pci_ctrl_dma_ch(struct rtw89_dev *rtwdev,
				  enum rtw89_pci_tx_channel txch,
				  bool enable)
{
	switch (txch) {
	case RTW89_PCI_TXCH_ACH0:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP1,
				   B_AX_STOP_ACH0, enable);
		break;
	case RTW89_PCI_TXCH_ACH1:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP1,
				   B_AX_STOP_ACH1, enable);
		break;
	case RTW89_PCI_TXCH_ACH2:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP1,
				   B_AX_STOP_ACH2, enable);
		break;
	case RTW89_PCI_TXCH_ACH3:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP1,
				   B_AX_STOP_ACH3, enable);
		break;
	case RTW89_PCI_TXCH_ACH4:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP1,
				   B_AX_STOP_ACH4, enable);
		break;
	case RTW89_PCI_TXCH_ACH5:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP1,
				   B_AX_STOP_ACH5, enable);
		break;
	case RTW89_PCI_TXCH_ACH6:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP1,
				   B_AX_STOP_ACH6, enable);
		break;
	case RTW89_PCI_TXCH_ACH7:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP1,
				   B_AX_STOP_ACH7, enable);
		break;
	case RTW89_PCI_TXCH_CH8:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP1,
				   B_AX_STOP_CH8, enable);
		break;
	case RTW89_PCI_TXCH_CH9:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP1,
				   B_AX_STOP_CH9, enable);
		break;
	case RTW89_PCI_TXCH_CH10:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP2,
				   B_AX_STOP_CH10, enable);
		break;
	case RTW89_PCI_TXCH_CH11:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP2,
				   B_AX_STOP_CH11, enable);
		break;
	case RTW89_PCI_TXCH_CH12:
		rtw89_write32_mask(rtwdev, R_AX_PCIE_DMA_STOP1,
				   B_AX_STOP_CH12, enable);
		break;
	default:
		rtw89_warn(rtwdev, "invalid dma channel control %d\n", txch);
		break;
	}
}

static int rtw89_pci_ops_mac_pre_init(struct rtw89_dev *rtwdev)
{
	enum rtw89_pci_tx_channel txch;
	u32 dma_busy;
	u32 check;
	int ret;

	if (1) {
		/* 8852AE A-Cut */
		rtw89_write32_set(rtwdev, R_AX_PCIE_INIT_CFG1,
				  B_AX_DIS_RXDMA_PRE);
		rtw89_write32_clr(rtwdev, R_AX_PCIE_RX_PREF_ADV,
				  B_AX_RXDMA_PREF_ADV_EN);
		rtw89_write32_set(rtwdev, R_AX_SYS_SDIO_CTRL,
				  B_AX_PCIE_AUXCLK_GATE);
	} else {
	}

	rtw89_write32_set(rtwdev, R_AX_PCIE_INIT_CFG1,
			  B_AX_PCIE_TXRST_KEEP_REG | B_AX_PCIE_RXRST_KEEP_REG);
	rtw89_write32_set(rtwdev, R_AX_PCIE_DMA_STOP1, B_AX_STOP_WPDMA);

	/* stop DMA activities */
	rtw89_pci_ctrl_dma_all(rtwdev, false);
	for (txch = 0; txch < RTW89_PCI_TXCH_NUM; txch++)
		rtw89_pci_ctrl_dma_ch(rtwdev, txch, false);

	/* check PCI at idle state */
	check = B_AX_PCIEIO_BUSY | B_AX_PCIEIO_TX_BUSY | B_AX_PCIEIO_RX_BUSY;
	ret = read_poll_timeout(rtw89_read32, dma_busy, (dma_busy & check) == 0,
				100, 3000, false, rtwdev, R_AX_PCIE_DMA_BUSY1);
	if (ret) {
		rtw89_err(rtwdev, "failed to poll io busy\n");
		return ret;
	}

	/* clear DMA indexes */
	rtw89_write32_set(rtwdev, R_AX_TXBD_RWPTR_CLR1,
			  B_AX_CLR_ACH0_IDX | B_AX_CLR_ACH1_IDX |
			  B_AX_CLR_ACH2_IDX | B_AX_CLR_ACH3_IDX |
			  B_AX_CLR_ACH4_IDX | B_AX_CLR_ACH5_IDX |
			  B_AX_CLR_ACH6_IDX | B_AX_CLR_ACH7_IDX |
			  B_AX_CLR_CH8_IDX | B_AX_CLR_CH9_IDX |
			  B_AX_CLR_CH12_IDX);
	rtw89_write32_set(rtwdev, R_AX_TXBD_RWPTR_CLR2,
			  B_AX_CLR_CH10_IDX | B_AX_CLR_CH11_IDX);
	rtw89_write32_set(rtwdev, R_AX_RXBD_RWPTR_CLR,
			  B_AX_CLR_RXQ_IDX | B_AX_CLR_RPQ_IDX);

	/* configure TX/RX op modes */
	rtw89_write32_set(rtwdev, R_AX_PCIE_INIT_CFG1, B_AX_TX_TRUNC_MODE |
						       B_AX_RX_TRUNC_MODE);
	rtw89_write32_clr(rtwdev, R_AX_PCIE_INIT_CFG1, B_AX_RXBD_MODE |
						       B_AX_LATENCY_CONTROL);

	/* TODO: DMA interval, leave it to default now */

	/* fill TRX BD indexes */
	rtw89_pci_reset_trx_rings(rtwdev);

	/* start DMA activities */
	for (txch = 0; txch < RTW89_PCI_TXCH_NUM; txch++)
		rtw89_pci_ctrl_dma_ch(rtwdev, txch, true);
	rtw89_pci_ctrl_dma_all(rtwdev, true);

	return 0;
}

static int rtw89_pci_ops_mac_post_init(struct rtw89_dev *rtwdev)
{
	return 0;
}

static u32 rtw89_pci_dma_recalc(struct rtw89_dev *rtwdev,
				struct rtw89_pci_dma_ring *bd_ring,
				u32 cur_idx, bool tx)
{
	u32 cnt, cur_rp, wp, rp, len;

	rp = bd_ring->rp;
	wp = bd_ring->wp;
	len = bd_ring->len;

	cur_rp = FIELD_GET(TXBD_HW_IDX_MASK, cur_idx);
	if (tx)
		cnt = cur_rp >= rp ? cur_rp - rp : len - (rp - cur_rp);
	else
		cnt = cur_rp >= wp ? cur_rp - wp : len - (wp - cur_rp);

	bd_ring->rp = cur_rp;

	return cnt;
}

static u32 rtw89_pci_txbd_recalc(struct rtw89_dev *rtwdev,
				 struct rtw89_pci_tx_ring *tx_ring)
{
	struct rtw89_pci_dma_ring *bd_ring = &tx_ring->bd_ring;
	u32 addr_idx = bd_ring->addr_idx;
	u32 cnt, idx;

	idx = rtw89_read32(rtwdev, addr_idx);
	cnt = rtw89_pci_dma_recalc(rtwdev, bd_ring, idx, true);

	return cnt;
}

static void rtw89_pci_isr_txch_dma(struct rtw89_dev *rtwdev,
				   struct rtw89_pci *rtwpci,
				   enum rtw89_pci_tx_channel txch)
{
	struct rtw89_pci_tx_ring *tx_ring = &rtwpci->tx_rings[txch];
	struct rtw89_pci_tx_wd *txwd;
	u32 cnt;

	spin_lock_bh(&rtwpci->trx_lock);

	cnt = rtw89_pci_txbd_recalc(rtwdev, tx_ring);
	if (!cnt) {
		rtw89_warn(rtwdev, "No TXBD consumed after DMA kicked off\n");
		goto out_unlock;
	}

	while (cnt--) {
		txwd = list_first_entry_or_null(&tx_ring->busy_pages,
						struct rtw89_pci_tx_wd, list);
		if (!txwd) {
			rtw89_warn(rtwdev, "No busy txwd pages available\n");
			break;
		}

		list_del(&txwd->list);
	}

out_unlock:
	spin_unlock_bh(&rtwpci->trx_lock);
}

static u32 rtw89_pci_rxbd_recalc(struct rtw89_dev *rtwdev,
				 struct rtw89_pci_rx_ring *rx_ring)
{
	struct rtw89_pci_dma_ring *bd_ring = &rx_ring->bd_ring;
	u32 addr_idx = bd_ring->addr_idx;
	u32 cnt, idx;

	idx = rtw89_read32(rtwdev, addr_idx);
	cnt = rtw89_pci_dma_recalc(rtwdev, bd_ring, idx, false);

	return cnt;
}

static void rtw89_pci_sync_skb_for_cpu(struct rtw89_dev *rtwdev,
				       struct sk_buff *skb)
{
	struct rtw89_pci_rx_info *rx_info;
	dma_addr_t dma;

	rx_info = RTW89_PCI_RX_SKB_CB(skb);
	dma = rx_info->dma;
	dma_sync_single_for_cpu(rtwdev->dev, dma, RTW89_PCI_RX_BUF_SIZE,
				DMA_FROM_DEVICE);
}

static void rtw89_pci_sync_skb_for_device(struct rtw89_dev *rtwdev,
					  struct sk_buff *skb)
{
	struct rtw89_pci_rx_info *rx_info;
	dma_addr_t dma;

	rx_info = RTW89_PCI_RX_SKB_CB(skb);
	dma = rx_info->dma;
	dma_sync_single_for_device(rtwdev->dev, dma, RTW89_PCI_RX_BUF_SIZE,
				   DMA_FROM_DEVICE);
}

static int rtw89_pci_rxbd_info_update(struct rtw89_dev *rtwdev,
				      struct sk_buff *skb)
{
	struct rtw89_pci_rxbd_info *rxbd_info;
	struct rtw89_pci_rx_info *rx_info = RTW89_PCI_RX_SKB_CB(skb);

	rxbd_info = (struct rtw89_pci_rxbd_info *)skb->data;
	rx_info->fs = le32_get_bits(rxbd_info->dword, RTW89_PCI_RXBD_FS);
	rx_info->ls = le32_get_bits(rxbd_info->dword, RTW89_PCI_RXBD_LS);
	rx_info->len = le32_get_bits(rxbd_info->dword, RTW89_PCI_RXBD_WRITE_SIZE);
	rx_info->tag = le32_get_bits(rxbd_info->dword, RTW89_PCI_RXBD_TAG);

	/* TODO: check RX tag */
	/* TODO: check RX len */

	rtw89_info(rtwdev, "consume RXBD, len %d, tag %d, fs/ls %d/%d\n",
		   rx_info->len, rx_info->tag, rx_info->fs, rx_info->ls);

	return 0;
}

static u32 rtw89_pci_rxbd_deliver_skbs(struct rtw89_dev *rtwdev,
				       struct rtw89_pci_rx_ring *rx_ring,
				       u32 max_rx_cnt)
{
	struct rtw89_pci_dma_ring *bd_ring = &rx_ring->bd_ring;
	struct rtw89_pci_rx_info *rx_info;
	struct rtw89_rx_desc_info desc_info;
	struct ieee80211_rx_status rx_status;
	struct sk_buff *skb, *new = NULL;
	u32 rxinfo_size = sizeof(struct rtw89_pci_rxbd_info);
	u32 offset;
	u32 cnt = 0;
	u8 rxdesc_len, shift_len, drv_info_len;
	int ret;

next_rxbd:
	if (cnt >= max_rx_cnt) {
		rtw89_err(rtwdev, "failed to deliver %d RXBD at %d\n",
			  max_rx_cnt, bd_ring->wp);
		goto out;
	}

	skb = rx_ring->buf[bd_ring->wp];
	rtw89_pci_sync_skb_for_cpu(rtwdev, skb);

	ret = rtw89_pci_rxbd_info_update(rtwdev, skb);
	if (ret) {
		rtw89_err(rtwdev, "failed to update %d RXBD info: %d\n",
			  bd_ring->wp, ret);
		goto out_sync_device;
	}

	rx_info = RTW89_PCI_RX_SKB_CB(skb);
	if (rx_info->fs) {
		/* should not set FS if not the first segment */
		if (cnt != 0) {
			rtw89_err(rtwdev, "multiple fs for RX frame, tag %d\n",
				  rx_info->tag);
			goto out_sync_device;
		}

		rtw89_core_query_rxdesc(rtwdev, &desc_info, skb->data + rxinfo_size);
		rtw89_core_update_rx_status(rtwdev, &desc_info, &rx_status);

		shift_len = desc_info.shift << 1; /* 2-byte unit */
		drv_info_len = desc_info.drv_info_size << 3; /* 8-byte unit */
		rxdesc_len = desc_info.long_rxdesc ?
			     sizeof(struct rtw89_rxdesc_long) :
			     sizeof(struct rtw89_rxdesc_short);
		offset = rxinfo_size + rxdesc_len + shift_len + drv_info_len;

		if (desc_info.pkt_type != RTW89_CORE_RX_TYPE_WIFI) {
			skb_pull(skb, offset);
			rtw89_core_rx_process_report(rtwdev, skb);
			goto out_sync_device;
		}

		new = dev_alloc_skb(desc_info.pkt_size);
		if (!new) {
			rtw89_err(rtwdev, "failed to allocate RX SKB\n");
			goto out_sync_device;
		}

		memcpy(new->cb, &rx_status, sizeof(rx_status));
		skb_put_data(new, skb->data + offset, rx_info->len - offset);
	} else {
		offset = rxinfo_size;

		skb_put_data(new, skb->data + offset, rx_info->len - offset);
	}

	rtw89_pci_sync_skb_for_device(rtwdev, skb);
	rtw89_pci_rxbd_increase(rx_ring, 1);
	cnt++;

	if (!rx_info->ls)
		goto next_rxbd;

	if (!new)
		goto out;

	ieee80211_rx_irqsafe(rtwdev->hw, new);
	return cnt;

out_sync_device:
	rtw89_pci_sync_skb_for_device(rtwdev, skb);
out:
	return cnt;
}

static void rtw89_pci_rxbd_deliver(struct rtw89_dev *rtwdev,
				   struct rtw89_pci_rx_ring *rx_ring,
				   u32 cnt)
{
	struct rtw89_pci_dma_ring *bd_ring = &rx_ring->bd_ring;
	u32 rx_cnt;

	while (cnt) {
		rx_cnt = rtw89_pci_rxbd_deliver_skbs(rtwdev, rx_ring, cnt);
		if (!rx_cnt) {
			rtw89_err(rtwdev, "failed to deliver RXBD skb\n");

			/* skip the rest RXBD bufs */
			rtw89_pci_rxbd_increase(rx_ring, cnt);
			break;
		}

		cnt -= rx_cnt;
	}

	rtw89_write16(rtwdev, bd_ring->addr_idx, bd_ring->wp);
}

static void rtw89_pci_isr_rxq_dma(struct rtw89_dev *rtwdev,
				  struct rtw89_pci *rtwpci)
{
	struct rtw89_pci_rx_ring *rx_ring;
	u32 cnt;

	rx_ring = &rtwpci->rx_rings[RTW89_PCI_RXCH_RXQ];

	spin_lock_bh(&rtwpci->trx_lock);

	cnt = rtw89_pci_rxbd_recalc(rtwdev, rx_ring);
	if (!cnt) {
		rtw89_warn(rtwdev, "No RX frame arrives from device\n");
		goto out_unlock;
	}

	rtw89_pci_rxbd_deliver(rtwdev, rx_ring, cnt);

out_unlock:
	spin_unlock_bh(&rtwpci->trx_lock);
}

static void rtw89_pci_release_rpp(struct rtw89_dev *rtwdev,
				  struct rtw89_pci_rpp_fmt *rpp)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	struct rtw89_pci_tx_ring *tx_ring;
	struct rtw89_pci_tx_wd_ring *wd_ring;
	struct rtw89_pci_tx_wd *txwd;
	struct rtw89_pci_tx_data *tx_data;
	struct sk_buff *skb, *tmp;
	struct ieee80211_tx_info *info;
	u16 seq;
	u8 mac_id, qsel, tx_status;
	bool polluted;

	seq = le32_get_bits(rpp->dword, RTW89_PCI_RPP_SEQ);
	mac_id = le32_get_bits(rpp->dword, RTW89_PCI_RPP_MACID);
	qsel = le32_get_bits(rpp->dword, RTW89_PCI_RPP_QSEL);
	tx_status = le32_get_bits(rpp->dword, RTW89_PCI_RPP_TX_STATUS);
	polluted = le32_get_bits(rpp->dword, RTW89_PCI_RPP_POLLUTED);

	tx_ring = &rtwpci->tx_rings[qsel];
	wd_ring = &tx_ring->wd_ring;
	txwd = &wd_ring->pages[seq];

	if (!list_empty(&txwd->list)) {
		rtw89_warn(rtwdev, "queue %d txwd %d is not idle\n",
			   qsel, seq);
		return;
	}

	/* currently, support for only one frame */
	if (skb_queue_len(&txwd->queue) != 1) {
		rtw89_warn(rtwdev, "empty pending queue %d page %d\n",
			   qsel, seq);
		return;
	}

	skb_queue_walk_safe(&txwd->queue, skb, tmp) {
		skb_unlink(skb, &txwd->queue);

		tx_data = RTW89_PCI_TX_SKB_CB(skb);
		pci_unmap_single(rtwpci->pdev, tx_data->dma, skb->len,
				 PCI_DMA_TODEVICE);

		info = IEEE80211_SKB_CB(skb);
		ieee80211_tx_info_clear_status(info);

		if (FIELD_GET(RTW89_PCI_TX_STATUS_ACK, tx_status))
			info->flags |= IEEE80211_TX_STAT_ACK;
		else if (info->flags & IEEE80211_TX_CTL_NO_ACK)
			info->flags |= IEEE80211_TX_STAT_NOACK_TRANSMITTED;

		ieee80211_tx_status_irqsafe(rtwdev->hw, skb);
	}

	list_add_tail(&txwd->list, &wd_ring->free_pages);
}

static u32 rtw89_pci_release_tx_skbs(struct rtw89_dev *rtwdev,
				     struct rtw89_pci_rx_ring *rx_ring,
				     u32 max_cnt)
{
	struct rtw89_pci_dma_ring *bd_ring = &rx_ring->bd_ring;
	struct rtw89_pci_rx_info *rx_info;
	struct rtw89_pci_rpp_fmt *rpp;
	struct sk_buff *skb;
	u32 cnt = 0;
	u32 rpp_size = sizeof(struct rtw89_pci_rpp_fmt);
	u32 rxinfo_size = sizeof(struct rtw89_pci_rxbd_info);
	u32 offset;
	int ret;

	skb = rx_ring->buf[bd_ring->wp];
	rtw89_pci_sync_skb_for_cpu(rtwdev, skb);

	ret = rtw89_pci_rxbd_info_update(rtwdev, skb);
	if (ret) {
		rtw89_err(rtwdev, "failed to update %d RXBD info: %d\n",
			  bd_ring->wp, ret);
		goto err_sync_device;
	}

	rx_info = RTW89_PCI_RX_SKB_CB(skb);
	if (!rx_info->fs || !rx_info->ls) {
		rtw89_err(rtwdev, "cannot process RP frame not set FS/LS\n");
		return cnt;
	}

	for (offset = rxinfo_size; offset + rpp_size <= rx_info->len;
	     offset += rpp_size) {
		rpp = (struct rtw89_pci_rpp_fmt *)(skb->data + offset);
		rtw89_pci_release_rpp(rtwdev, rpp);
	}

	rtw89_pci_sync_skb_for_device(rtwdev, skb);
	rtw89_pci_rxbd_increase(rx_ring, 1);
	cnt++;

	return cnt;

err_sync_device:
	rtw89_pci_sync_skb_for_device(rtwdev, skb);
	return 0;
}

static void rtw89_pci_release_tx(struct rtw89_dev *rtwdev,
				 struct rtw89_pci_rx_ring *rx_ring,
				 u32 cnt)
{
	struct rtw89_pci_dma_ring *bd_ring = &rx_ring->bd_ring;
	u32 release_cnt;

	while (cnt) {
		release_cnt = rtw89_pci_release_tx_skbs(rtwdev, rx_ring, cnt);
		if (!release_cnt) {
			rtw89_err(rtwdev, "failed to release TX skbs\n");

			/* skip the rest RXBD bufs */
			rtw89_pci_rxbd_increase(rx_ring, cnt);
			break;
		}

		cnt -= release_cnt;
	}

	rtw89_write16(rtwdev, bd_ring->addr_idx, bd_ring->wp);
}

static void rtw89_pci_isr_rpq_dma(struct rtw89_dev *rtwdev,
				  struct rtw89_pci *rtwpci)
{
	struct rtw89_pci_rx_ring *rx_ring;
	u32 cnt;

	rx_ring = &rtwpci->rx_rings[RTW89_PCI_RXCH_RPQ];

	spin_lock_bh(&rtwpci->trx_lock);

	cnt = rtw89_pci_rxbd_recalc(rtwdev, rx_ring);
	if (!cnt) {
		rtw89_warn(rtwdev, "No RP frame arrives from device\n");
		goto out_unlock;
	}

	rtw89_pci_release_tx(rtwdev, rx_ring, cnt);

out_unlock:
	spin_unlock_bh(&rtwpci->trx_lock);
}

static void rtw89_pci_isr_rxd_unavail(struct rtw89_dev *rtwdev,
				      struct rtw89_pci *rtwpci)
{
	struct rtw89_pci_rx_ring *rx_ring;
	struct rtw89_pci_dma_ring *bd_ring;
	u32 reg_idx;
	int i;

	for (i = 0; i < RTW89_PCI_RXCH_NUM; i++) {
		rx_ring = &rtwpci->rx_rings[i];
		bd_ring = &rx_ring->bd_ring;

		reg_idx = rtw89_read32(rtwdev, bd_ring->addr_idx);

		rtw89_warn(rtwdev, "%d RXD unavailable, idx=0x%08x, len=%d\n",
			   i, reg_idx, bd_ring->len);
	}
}

static void rtw89_pci_clear_intrs(struct rtw89_dev *rtwdev,
				  struct rtw89_pci *rtwpci)
{
	rtw89_write32(rtwdev, R_AX_PCIE_HISR00, rtwpci->isrs[0]);
	rtw89_write32(rtwdev, R_AX_PCIE_HISR10, rtwpci->isrs[1]);
}

static void rtw89_pci_recognize_intrs(struct rtw89_dev *rtwdev,
				      struct rtw89_pci *rtwpci)
{
	rtwpci->isrs[0] = rtw89_read32(rtwdev, R_AX_PCIE_HISR00);
	rtwpci->isrs[1] = rtw89_read32(rtwdev, R_AX_PCIE_HISR10);
}

static void rtw89_pci_enable_intr(struct rtw89_dev *rtwdev,
				  struct rtw89_pci *rtwpci)
{
	rtw89_write32(rtwdev, R_AX_PCIE_HIMR00, rtwpci->intrs[0]);
	rtw89_write32(rtwdev, R_AX_PCIE_HIMR10, rtwpci->intrs[1]);
}

static void rtw89_pci_disable_intr(struct rtw89_dev *rtwdev,
				   struct rtw89_pci *rtwpci)
{
	rtw89_write32(rtwdev, R_AX_PCIE_HIMR00, 0);
	rtw89_write32(rtwdev, R_AX_PCIE_HIMR10, 0);
}

static irqreturn_t rtw89_pci_interrupt_threadfn(int irq, void *dev)
{
	struct rtw89_dev *rtwdev = dev;
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	u32 intrs[2];
	unsigned long flags;

	intrs[0] = rtwpci->intrs[0];
	intrs[1] = rtwpci->intrs[1];

	/* TX ISR */
	if (intrs[0] & B_AX_TXDMA_ACH0_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_ACH0);
	if (intrs[0] & B_AX_TXDMA_ACH1_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_ACH1);
	if (intrs[0] & B_AX_TXDMA_ACH2_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_ACH2);
	if (intrs[0] & B_AX_TXDMA_ACH3_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_ACH3);
	if (intrs[0] & B_AX_TXDMA_ACH4_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_ACH4);
	if (intrs[0] & B_AX_TXDMA_ACH5_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_ACH5);
	if (intrs[0] & B_AX_TXDMA_ACH6_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_ACH6);
	if (intrs[0] & B_AX_TXDMA_ACH7_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_ACH7);
	if (intrs[0] & B_AX_TXDMA_CH8_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_CH8);
	if (intrs[0] & B_AX_TXDMA_CH9_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_CH9);
	if (intrs[0] & B_AX_TXDMA_CH12_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_CH12);
	if (intrs[1] & B_AX_TXDMA_CH10_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_CH10);
	if (intrs[1] & B_AX_TXDMA_CH11_INT)
		rtw89_pci_isr_txch_dma(rtwdev, rtwpci, RTW89_PCI_TXCH_CH11);

	/* RX ISR */
	if (intrs[0] & (B_AX_RXDMA_INT | B_AX_RXP1DMA_INT))
		rtw89_pci_isr_rxq_dma(rtwdev, rtwpci);
	if (intrs[0] & B_AX_RPQDMA_INT)
		rtw89_pci_isr_rpq_dma(rtwdev, rtwpci);
	if (intrs[0] & B_AX_RDU_INT)
		rtw89_pci_isr_rxd_unavail(rtwdev, rtwpci);

	spin_lock_irqsave(&rtwpci->irq_lock, flags);
	rtw89_pci_clear_intrs(rtwdev, rtwpci);
	rtw89_pci_enable_intr(rtwdev, rtwpci);
	spin_unlock_irqrestore(&rtwpci->irq_lock, flags);

	return IRQ_HANDLED;
}

static irqreturn_t rtw89_pci_interrupt_handler(int irq, void *dev)
{
	struct rtw89_dev *rtwdev = dev;
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	unsigned long flags;

	/* Disable interrupt here to avoid more interrupts being issued before
	 * the threadfn ends.
	 */
	spin_lock_irqsave(&rtwpci->irq_lock, flags);
	rtw89_pci_disable_intr(rtwdev, rtwpci);
	rtw89_pci_recognize_intrs(rtwdev, rtwpci);
	spin_unlock_irqrestore(&rtwpci->irq_lock, flags);

	return IRQ_WAKE_THREAD;
}

static int rtw89_pci_claim_device(struct rtw89_dev *rtwdev,
				  struct pci_dev *pdev)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	int ret;

	ret = pci_enable_device(pdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to enable pci device\n");
		return ret;
	}

	pci_set_master(pdev);
	pci_set_drvdata(pdev, rtwdev->hw);

	rtwpci->pdev = pdev;

	return 0;
}

static void rtw89_pci_declaim_device(struct rtw89_dev *rtwdev,
				     struct pci_dev *pdev)
{
	pci_clear_master(pdev);
	pci_disable_device(pdev);
}

static int rtw89_pci_setup_mapping(struct rtw89_dev *rtwdev,
				   struct pci_dev *pdev)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	unsigned long resource_len;
	u8 bar_id = 2;
	int ret;

	ret = pci_request_regions(pdev, KBUILD_MODNAME);
	if (ret) {
		rtw89_err(rtwdev, "failed to request pci regions\n");
		goto err;
	}

	ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
	if (ret) {
		rtw89_err(rtwdev, "failed to set dma mask to 32-bit\n");
		goto err_release_regions;
	}

	ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
	if (ret) {
		rtw89_err(rtwdev, "failed to set consistent dma mask to 32-bit\n");
		goto err_release_regions;
	}

	resource_len = pci_resource_len(pdev, bar_id);
	rtwpci->mmap = pci_iomap(pdev, bar_id, resource_len);
	if (!rtwpci->mmap) {
		rtw89_err(rtwdev, "failed to map pci io\n");
		ret = -EIO;
		goto err_release_regions;
	}

	return 0;

err_release_regions:
	pci_release_regions(pdev);
err:
	return ret;
}

static void rtw89_pci_clear_mapping(struct rtw89_dev *rtwdev,
				    struct pci_dev *pdev)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;

	if (rtwpci->mmap) {
		pci_iounmap(pdev, rtwpci->mmap);
		pci_release_regions(pdev);
	}
}

static void rtw89_pci_free_tx_wd_ring(struct rtw89_dev *rtwdev,
				      struct pci_dev *pdev,
				      struct rtw89_pci_tx_ring *tx_ring)
{
	struct rtw89_pci_tx_wd_ring *wd_ring = &tx_ring->wd_ring;
	u8 *head = wd_ring->head;
	dma_addr_t dma = wd_ring->dma;
	u32 page_size = wd_ring->page_size;
	u32 page_num = wd_ring->page_num;
	u32 ring_sz = page_size * page_num;

	pci_free_consistent(pdev, ring_sz, head, dma);
	wd_ring->head = NULL;
}

static void rtw89_pci_free_tx_ring(struct rtw89_dev *rtwdev,
				   struct pci_dev *pdev,
				   struct rtw89_pci_tx_ring *tx_ring)
{
	int ring_sz;
	u8 *head;
	dma_addr_t dma;

	head = tx_ring->bd_ring.head;
	dma = tx_ring->bd_ring.dma;
	ring_sz = tx_ring->bd_ring.desc_size * tx_ring->bd_ring.len;
	pci_free_consistent(pdev, ring_sz, head, dma);

	tx_ring->bd_ring.head = NULL;
}

static void rtw89_pci_free_tx_rings(struct rtw89_dev *rtwdev,
				    struct pci_dev *pdev)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	struct rtw89_pci_tx_ring *tx_ring;
	int i;

	for (i = 0; i < RTW89_PCI_TXCH_NUM; i++) {
		tx_ring = &rtwpci->tx_rings[i];
		rtw89_pci_free_tx_wd_ring(rtwdev, pdev, tx_ring);
		rtw89_pci_free_tx_ring(rtwdev, pdev, tx_ring);
	}
}

static void rtw89_pci_free_rx_ring(struct rtw89_dev *rtwdev,
				   struct pci_dev *pdev,
				   struct rtw89_pci_rx_ring *rx_ring)
{
	struct rtw89_pci_rx_info *rx_info;
	struct sk_buff *skb;
	dma_addr_t dma;
	u32 buf_sz;
	u8 *head;
	int ring_sz = rx_ring->bd_ring.desc_size * rx_ring->bd_ring.len;
	int i;

	buf_sz = rx_ring->buf_sz;
	for (i = 0; i < rx_ring->bd_ring.len; i++) {
		skb = rx_ring->buf[i];
		if (!skb)
			continue;

		rx_info = RTW89_PCI_RX_SKB_CB(skb);
		dma = rx_info->dma;
		pci_unmap_single(pdev, dma, buf_sz, PCI_DMA_FROMDEVICE);
		dev_kfree_skb(skb);
		rx_ring->buf[i] = NULL;
	}

	head = rx_ring->bd_ring.head;
	dma = rx_ring->bd_ring.dma;
	pci_free_consistent(pdev, ring_sz, head, dma);

	rx_ring->bd_ring.head = NULL;
}

static void rtw89_pci_free_rx_rings(struct rtw89_dev *rtwdev,
				    struct pci_dev *pdev)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	struct rtw89_pci_rx_ring *rx_ring;
	int i;

	for (i = 0; i < RTW89_PCI_RXCH_NUM; i++) {
		rx_ring = &rtwpci->rx_rings[i];
		rtw89_pci_free_rx_ring(rtwdev, pdev, rx_ring);
	}
}

static void rtw89_pci_free_trx_rings(struct rtw89_dev *rtwdev,
				     struct pci_dev *pdev)
{
	rtw89_pci_free_rx_rings(rtwdev, pdev);
	rtw89_pci_free_tx_rings(rtwdev, pdev);
}

static int rtw89_pci_init_rx_bd(struct rtw89_dev *rtwdev, struct pci_dev *pdev,
				struct rtw89_pci_rx_ring *rx_ring,
				struct sk_buff *skb, int buf_sz, u32 idx)
{
	struct rtw89_pci_rx_info *rx_info;
	struct rtw89_pci_rx_bd_32 *rx_bd;
	dma_addr_t dma;

	if (!skb)
		return -EINVAL;

	dma = pci_map_single(pdev, skb->data, buf_sz, PCI_DMA_FROMDEVICE);
	if (pci_dma_mapping_error(pdev, dma))
		return -EBUSY;

	rx_info = RTW89_PCI_RX_SKB_CB(skb);
	rx_bd = RTW89_PCI_RX_BD(rx_ring, idx);

	memset(rx_bd, 0, sizeof(*rx_bd));
	rx_bd->buf_size = cpu_to_le16(buf_sz);
	rx_bd->dma = cpu_to_le32(dma);
	rx_info->dma = dma;

	return 0;
}

static int rtw89_pci_alloc_tx_wd_ring(struct rtw89_dev *rtwdev,
				      struct pci_dev *pdev,
				      struct rtw89_pci_tx_ring *tx_ring)
{
	struct rtw89_pci_tx_wd_ring *wd_ring = &tx_ring->wd_ring;
	struct rtw89_pci_tx_wd *txwd;
	dma_addr_t dma;
	dma_addr_t cur_paddr;
	u8 *head;
	u8 *cur_vaddr;
	u32 page_size = RTW89_PCI_TXWD_PAGE_SIZE;
	u32 page_num = RTW89_PCI_TXWD_NUM_MAX;
	u32 ring_sz = page_size * page_num;
	u32 page_offset;
	int i;

	head = pci_zalloc_consistent(pdev, ring_sz, &dma);
	if (!head) {
		rtw89_err(rtwdev, "failed to alloc tx wd dma ring\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&wd_ring->free_pages);
	wd_ring->head = head;
	wd_ring->dma = dma;
	wd_ring->page_size = page_size;
	wd_ring->page_num = page_num;

	page_offset = 0;
	for (i = 0; i < page_num; i++) {
		txwd = &wd_ring->pages[i];
		cur_paddr = dma + page_offset;
		cur_vaddr = head + page_offset;

		skb_queue_head_init(&txwd->queue);
		INIT_LIST_HEAD(&txwd->list);
		list_add_tail(&txwd->list, &wd_ring->free_pages);
		txwd->paddr = cur_paddr;
		txwd->vaddr = cur_vaddr;
		txwd->seq = i;

		page_offset += page_size;
	}

	return 0;
}

static int rtw89_pci_alloc_tx_ring(struct rtw89_dev *rtwdev,
				   struct pci_dev *pdev,
				   struct rtw89_pci_tx_ring *tx_ring,
				   u32 desc_size, u32 len,
				   enum rtw89_pci_tx_channel txch)
{
	int ring_sz = desc_size * len;
	u8 *head;
	dma_addr_t dma;
	u32 addr_num;
	u32 addr_idx;
	u32 addr_desa;
	int ret;

	ret = rtw89_pci_alloc_tx_wd_ring(rtwdev, pdev, tx_ring);
	if (ret) {
		rtw89_err(rtwdev, "failed to alloc txwd ring of txch %d\n", txch);
		goto err;
	}

	ret = rtw89_pci_get_txch_addrs(txch, &addr_num, &addr_idx, &addr_desa);
	if (ret) {
		rtw89_err(rtwdev, "failed to get address of txch %d", txch);
		goto err_free_wd_ring;
	}

	head = pci_zalloc_consistent(pdev, ring_sz, &dma);
	if (!head) {
		rtw89_err(rtwdev, "failed to alloc pci dma consistent\n");
		ret = -ENOMEM;
		goto err_free_wd_ring;
	}

	INIT_LIST_HEAD(&tx_ring->busy_pages);
	tx_ring->bd_ring.head = head;
	tx_ring->bd_ring.dma = dma;
	tx_ring->bd_ring.len = len;
	tx_ring->bd_ring.desc_size = desc_size;
	tx_ring->bd_ring.addr_num = addr_num;
	tx_ring->bd_ring.addr_idx = addr_idx;
	tx_ring->bd_ring.addr_desa = addr_desa;
	tx_ring->bd_ring.wp = 0;
	tx_ring->bd_ring.rp = 0;

	return 0;

err_free_wd_ring:
	rtw89_pci_free_tx_wd_ring(rtwdev, pdev, tx_ring);
err:
	return ret;
}

static int rtw89_pci_alloc_tx_rings(struct rtw89_dev *rtwdev,
				    struct pci_dev *pdev)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	struct rtw89_pci_tx_ring *tx_ring;
	u32 desc_size;
	u32 len;
	u32 i, tx_allocated;
	int ret;

	for (i = 0; i < RTW89_PCI_TXCH_NUM; i++) {
		tx_ring = &rtwpci->tx_rings[i];
		desc_size = sizeof(struct rtw89_pci_tx_bd_32);
		len = RTW89_PCI_TXBD_NUM_MAX;
		ret = rtw89_pci_alloc_tx_ring(rtwdev, pdev, tx_ring,
					      desc_size, len, i);
		if (ret) {
			rtw89_err(rtwdev, "failed to alloc tx ring %d\n", i);
			goto err_free;
		}
	}

	return 0;

err_free:
	tx_allocated = i;
	for (i = 0; i < tx_allocated; i++) {
		tx_ring = &rtwpci->tx_rings[i];
		rtw89_pci_free_tx_ring(rtwdev, pdev, tx_ring);
	}

	return ret;
}

static int rtw89_pci_alloc_rx_ring(struct rtw89_dev *rtwdev,
				   struct pci_dev *pdev,
				   struct rtw89_pci_rx_ring *rx_ring,
				   u32 desc_size, u32 len, u32 rxch)
{
	struct sk_buff *skb;
	u8 *head;
	dma_addr_t dma;
	u32 addr_num;
	u32 addr_idx;
	u32 addr_desa;
	int ring_sz = desc_size * len;
	int buf_sz = RTW89_PCI_RX_BUF_SIZE;
	int i, allocated;
	int ret;

	ret = rtw89_pci_get_rxch_addrs(rxch, &addr_num, &addr_idx, &addr_desa);
	if (ret) {
		rtw89_err(rtwdev, "failed to get address of rxch %d", rxch);
		return ret;
	}

	head = pci_zalloc_consistent(pdev, ring_sz, &dma);
	if (!head) {
		rtw89_err(rtwdev, "failed to alloc pci dma consistent\n");
		ret = -ENOMEM;
		goto err;
	}

	rx_ring->bd_ring.head = head;
	rx_ring->bd_ring.dma = dma;
	rx_ring->bd_ring.len = len;
	rx_ring->bd_ring.desc_size = desc_size;
	rx_ring->bd_ring.addr_num = addr_num;
	rx_ring->bd_ring.addr_idx = addr_idx;
	rx_ring->bd_ring.addr_desa = addr_desa;
	rx_ring->bd_ring.wp = 0;
	rx_ring->bd_ring.rp = 0;
	rx_ring->buf_sz = buf_sz;

	for (i = 0; i < len; i++) {
		skb = dev_alloc_skb(buf_sz);
		if (!skb) {
			rtw89_err(rtwdev, "failed to alloc rx buf %d\n", i);
			ret = -ENOMEM;
			goto err_free;
		}

		memset(skb->data, 0, buf_sz);
		rx_ring->buf[i] = skb;
		ret = rtw89_pci_init_rx_bd(rtwdev, pdev, rx_ring, skb,
					   buf_sz, i);
		if (ret) {
			rtw89_err(rtwdev, "failed to init rx buf %d\n", i);
			dev_kfree_skb_any(skb);
			rx_ring->buf[i] = NULL;
			goto err_free;
		}
	}

	return 0;

err_free:
	allocated = i;
	for (i = 0; i < allocated; i++) {
		skb = rx_ring->buf[i];
		if (!skb)
			continue;
		dma = *((dma_addr_t *)skb->cb);
		pci_unmap_single(pdev, dma, buf_sz, PCI_DMA_FROMDEVICE);
		dev_kfree_skb(skb);
		rx_ring->buf[i] = NULL;
	}

	head = rx_ring->bd_ring.head;
	dma = rx_ring->bd_ring.dma;
	pci_free_consistent(pdev, ring_sz, head, dma);

	rx_ring->bd_ring.head = NULL;
err:
	return ret;
}

static int rtw89_pci_alloc_rx_rings(struct rtw89_dev *rtwdev,
				    struct pci_dev *pdev)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	struct rtw89_pci_rx_ring *rx_ring;
	u32 desc_size;
	u32 len;
	int i, rx_allocated;
	int ret;

	for (i = 0; i < RTW89_PCI_RXCH_NUM; i++) {
		rx_ring = &rtwpci->rx_rings[i];
		desc_size = sizeof(struct rtw89_pci_rx_bd_32);
		len = RTW89_PCI_RXBD_NUM_MAX;
		ret = rtw89_pci_alloc_rx_ring(rtwdev, pdev, rx_ring,
					      desc_size, len, i);
		if (ret) {
			rtw89_err(rtwdev, "failed to alloc rx ring %d\n", i);
			goto err_free;
		}
	}

	return 0;

err_free:
	rx_allocated = i;
	for (i = 0; i < rx_allocated; i++) {
		rx_ring = &rtwpci->rx_rings[i];
		rtw89_pci_free_rx_ring(rtwdev, pdev, rx_ring);
	}

	return ret;
}

static int rtw89_pci_alloc_trx_rings(struct rtw89_dev *rtwdev,
				     struct pci_dev *pdev)
{
	int ret;

	ret = rtw89_pci_alloc_tx_rings(rtwdev, pdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to alloc dma tx rings\n");
		goto err;
	}

	ret = rtw89_pci_alloc_rx_rings(rtwdev, pdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to alloc dma rx rings\n");
		goto err_free_tx_rings;
	}

	return 0;

err_free_tx_rings:
	rtw89_pci_free_tx_rings(rtwdev, pdev);
err:
	return ret;
}

static int rtw89_pci_setup_resource(struct rtw89_dev *rtwdev,
				    struct pci_dev *pdev)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	int ret;

	ret = rtw89_pci_setup_mapping(rtwdev, pdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to setup pci mapping\n");
		goto err;
	}

	ret = rtw89_pci_alloc_trx_rings(rtwdev, pdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to alloc pci trx rings\n");
		goto err_pci_unmap;
	}

	spin_lock_init(&rtwpci->irq_lock);
	spin_lock_init(&rtwpci->trx_lock);

	return 0;

err_pci_unmap:
	rtw89_pci_clear_mapping(rtwdev, pdev);
err:
	return ret;
}

static void rtw89_pci_clear_resource(struct rtw89_dev *rtwdev,
				     struct pci_dev *pdev)
{
	rtw89_pci_free_trx_rings(rtwdev, pdev);
	rtw89_pci_clear_mapping(rtwdev, pdev);
}

static void rtw89_pci_default_intr_mask(struct rtw89_dev *rtwdev)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;

	rtwpci->intrs[0] = B_AX_TXDMA_ACH0_INT_EN |
			   B_AX_TXDMA_ACH1_INT_EN |
			   B_AX_TXDMA_ACH2_INT_EN |
			   B_AX_TXDMA_ACH3_INT_EN |
			   B_AX_TXDMA_ACH4_INT_EN |
			   B_AX_TXDMA_ACH5_INT_EN |
			   B_AX_TXDMA_ACH6_INT_EN |
			   B_AX_TXDMA_ACH7_INT_EN |
			   B_AX_TXDMA_CH8_INT_EN |
			   B_AX_TXDMA_CH9_INT_EN |
			   B_AX_TXDMA_CH12_INT_EN |
			   B_AX_TXDMA_STUCK_INT_EN |
			   B_AX_RXDMA_INT_EN |
			   B_AX_RXP1DMA_INT_EN |
			   B_AX_RPQDMA_INT_EN |
			   B_AX_RXDMA_STUCK_INT_EN |
			   B_AX_RDU_INT_EN |
			   B_AX_RPQBD_FULL_INT_EN;

	rtwpci->intrs[1] = B_AX_TXDMA_CH11_INT_EN |
			   B_AX_TXDMA_CH10_INT_EN |
			   B_AX_HC10ISR_IND_INT_EN;
}

static int rtw89_pci_request_irq(struct rtw89_dev *rtwdev,
				 struct pci_dev *pdev)
{
	unsigned long flags = 0;
	int ret;

	flags |= PCI_IRQ_LEGACY | PCI_IRQ_MSI;
	ret = pci_alloc_irq_vectors(pdev, 1, 1, flags);
	if (ret < 0) {
		rtw89_err(rtwdev, "failed to alloc irq vectors, ret %d\n", ret);
		goto err;
	}

	ret = devm_request_threaded_irq(rtwdev->dev, pdev->irq,
					rtw89_pci_interrupt_handler,
					rtw89_pci_interrupt_threadfn,
					IRQF_SHARED, KBUILD_MODNAME, rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to request threaded irq\n");
		goto err_free_vector;
	}

	rtw89_pci_default_intr_mask(rtwdev);

	return 0;

err_free_vector:
	pci_free_irq_vectors(pdev);
err:
	return ret;
}

static void rtw89_pci_free_irq(struct rtw89_dev *rtwdev,
			       struct pci_dev *pdev)
{
	devm_free_irq(rtwdev->dev, pdev->irq, rtwdev);
	pci_free_irq_vectors(pdev);
}

static const struct rtw89_hci_ops rtw89_pci_ops = {
	.tx		= rtw89_pci_ops_tx,
	.reset		= rtw89_pci_ops_reset,

	.read8		= rtw89_pci_ops_read8,
	.read16		= rtw89_pci_ops_read16,
	.read32		= rtw89_pci_ops_read32,
	.write8		= rtw89_pci_ops_write8,
	.write16	= rtw89_pci_ops_write16,
	.write32	= rtw89_pci_ops_write32,

	.mac_pre_init	= rtw89_pci_ops_mac_pre_init,
	.mac_post_init	= rtw89_pci_ops_mac_post_init,
};

static int rtw89_pci_probe(struct pci_dev *pdev,
			   const struct pci_device_id *id)
{
	struct ieee80211_hw *hw;
	struct rtw89_dev *rtwdev;
	int driver_data_size;
	int ret;

	driver_data_size = sizeof(struct rtw89_dev) + sizeof(struct rtw89_pci);
	hw = ieee80211_alloc_hw(driver_data_size, &rtw89_ops);
	if (!hw) {
		dev_err(&pdev->dev, "failed to allocate hw\n");
		return -ENOMEM;
	}

	rtwdev = hw->priv;
	rtwdev->hw = hw;
	rtwdev->dev = &pdev->dev;
	rtwdev->hci.ops = &rtw89_pci_ops;
	rtwdev->hci.type = RTW89_HCI_TYPE_PCIE;

	SET_IEEE80211_DEV(rtwdev->hw, &pdev->dev);

	switch (id->driver_data) {
	case RTL8852A:
		rtwdev->chip = &rtw8852a_chip_info;
		break;
	default:
		return -ENOENT;
	}

	ret = rtw89_pci_claim_device(rtwdev, pdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to claim pci device\n");
		goto err_release_hw;
	}

	ret = rtw89_pci_setup_resource(rtwdev, pdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to setup pci resource\n");
		goto err_declaim_pci;
	}

	ret = rtw89_core_register(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to register core\n");
		goto err_clear_resource;
	}

	ret = rtw89_pci_request_irq(rtwdev, pdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to request pci irq\n");
		goto err_unregister;
	}

	return 0;

err_unregister:
	rtw89_core_unregister(rtwdev);
err_clear_resource:
	rtw89_pci_clear_resource(rtwdev, pdev);
err_declaim_pci:
	rtw89_pci_declaim_device(rtwdev, pdev);
err_release_hw:
	ieee80211_free_hw(hw);

	return ret;
}

static void rtw89_pci_remove(struct pci_dev *pdev)
{
	struct ieee80211_hw *hw = pci_get_drvdata(pdev);
	struct rtw89_dev *rtwdev;
	struct rtw89_pci *rtwpci;

	if (!hw)
		return;

	rtwdev = hw->priv;
	rtwpci = (struct rtw89_pci *)rtwdev->priv;

	rtw89_pci_free_irq(rtwdev, pdev);
	rtw89_core_unregister(rtwdev);
	rtw89_pci_clear_resource(rtwdev, pdev);
	rtw89_pci_declaim_device(rtwdev, pdev);
	ieee80211_free_hw(hw);
}

static const struct pci_device_id rtw89_pci_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_REALTEK, 0x8852), .driver_data = RTL8852A },
	{},
};

static struct pci_driver rtw89_pci_driver = {
	.name		= "rtw89_pci",
	.id_table	= rtw89_pci_id_table,
	.probe		= rtw89_pci_probe,
	.remove		= rtw89_pci_remove,
};
module_pci_driver(rtw89_pci_driver);

MODULE_AUTHOR("Realtek Corporation");
MODULE_DESCRIPTION("Realtek 802.11ax wireless PCI driver");
MODULE_LICENSE("Dual BSD/GPL");
