// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include <linux/module.h>
#include <linux/usb.h>
#include <linux/mutex.h>
#include "core.h"
#include "debug.h"
#include "usb.h"

#define RTW_USB_MSG_TIMEOUT	3000 /* (ms) */

static void rtw_usb_tx_agg(struct rtw_usb *rtwusb, struct sk_buff *skb);
static void rtw_usb_read_port(struct rtw89_dev *rtwdev, u8 addr,
			      struct rx_usb_ctrl_block *rxcb);
static void rtw_usb_tx_agg(struct rtw_usb *rtwusb, struct sk_buff *skb);

/*
 * usb read/write register functions
 */

static u8 rtw_usb_read8(struct rtw89_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int len;
	u8 data;

	mutex_lock(&rtwusb->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			      addr, 0, &rtwusb->usb_buf.val8,
			      sizeof(rtwusb->usb_buf.val8),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = rtwusb->usb_buf.val8;
	mutex_unlock(&rtwusb->usb_buf_mutex);

	return data;
}

static u16 rtw_usb_read16(struct rtw89_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int len;
	u16 data;

	mutex_lock(&rtwusb->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			      addr, 0, &rtwusb->usb_buf.val16,
			      sizeof(rtwusb->usb_buf.val16),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = le16_to_cpu(rtwusb->usb_buf.val16);
	mutex_unlock(&rtwusb->usb_buf_mutex);

	return data;
}

static u32 rtw_usb_read32(struct rtw89_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int len;
	u32 data;

	mutex_lock(&rtwusb->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			      addr, 0, &rtwusb->usb_buf.val32,
			      sizeof(rtwusb->usb_buf.val32),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = le32_to_cpu(rtwusb->usb_buf.val32);
	mutex_unlock(&rtwusb->usb_buf_mutex);

	return data;
}

static void rtw_usb_write8(struct rtw89_dev *rtwdev, u32 addr, u8 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int ret;

	mutex_lock(&rtwusb->usb_buf_mutex);
	rtwusb->usb_buf.val8 = val;
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			      addr, 0, &rtwusb->usb_buf.val8,
			      sizeof(rtwusb->usb_buf.val8),
			      RTW_USB_CONTROL_MSG_TIMEOUT);

	mutex_unlock(&rtwusb->usb_buf_mutex);
}

static void rtw_usb_write16(struct rtw89_dev *rtwdev, u32 addr, u16 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int ret;

	mutex_lock(&rtwusb->usb_buf_mutex);
	rtwusb->usb_buf.val16 = cpu_to_le16(val);
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			      addr, 0, &rtwusb->usb_buf.val16,
			      sizeof(rtwusb->usb_buf.val16),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	mutex_unlock(&rtwusb->usb_buf_mutex);
}

static void rtw_usb_write32(struct rtw89_dev *rtwdev, u32 addr, u32 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int ret;

	mutex_lock(&rtwusb->usb_buf_mutex);
	rtwusb->usb_buf.val32 = cpu_to_le32(val);
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			      addr, 0, &rtwusb->usb_buf.val32,
			      sizeof(rtwusb->usb_buf.val32),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	mutex_unlock(&rtwusb->usb_buf_mutex);
}

static int rtw_usb_parse(struct rtw89_dev *rtwdev,
			 struct usb_interface *interface)
{
	struct rtw_usb *rtwusb;
	struct usb_interface_descriptor *interface_desc;
	struct usb_host_interface *host_interface;
	struct usb_endpoint_descriptor *endpoint;
	struct device *dev;
	struct usb_device *usbd;
	int i, j = 0, endpoints;
	u8 dir, xtype, num;
	int ret = 0;

	rtwusb = rtw_get_usb_priv(rtwdev);

	dev = &rtwusb->udev->dev;

	usbd = interface_to_usbdev(interface);
	host_interface = &interface->altsetting[0];
	interface_desc = &host_interface->desc;
	endpoints = interface_desc->bNumEndpoints;

	rtwusb->num_in_pipes = 0;
	rtwusb->num_out_pipes = 0;
	for (i = 0; i < endpoints; i++) {
		endpoint = &host_interface->endpoint[i].desc;
		dir = endpoint->bEndpointAddress & USB_ENDPOINT_DIR_MASK;
		num = usb_endpoint_num(endpoint);
		xtype = usb_endpoint_type(endpoint);
		//dev_dbg(dev,
		//		"%s: endpoint: dir %02x, # %02x, type %02x\n",
		//		__func__, dir, num, xtype);
		pr_info("\nusb endpoint descriptor (%i):\n", i);
		pr_info("bLength=%x\n", endpoint->bLength);
		pr_info("bDescriptorType=%x\n", endpoint->bDescriptorType);
		pr_info("bEndpointAddress=%x\n", endpoint->bEndpointAddress);
		pr_info("wMaxPacketSize=%d\n",
			 le16_to_cpu(endpoint->wMaxPacketSize));
		pr_info("bInterval=%x\n", endpoint->bInterval);

		if (usb_endpoint_dir_in(endpoint) &&
		    usb_endpoint_xfer_bulk(endpoint)) {
			dev_dbg(dev, "%s: in endpoint num %i\n", __func__, num);

			if (rtwusb->pipe_in) {
				dev_warn(dev, "%s: Too many IN pipes\n",
					 __func__);
				ret = -EINVAL;
				goto exit;
			}

			rtwusb->pipe_in = num;
			rtwusb->num_in_pipes++;
		}

		if (usb_endpoint_dir_in(endpoint) &&
		    usb_endpoint_xfer_int(endpoint)) {
			dev_dbg(dev, "%s: interrupt endpoint num %i\n",
				__func__, num);

			if (rtwusb->pipe_interrupt) {
				dev_warn(dev, "%s: Too many INTERRUPT pipes\n",
					 __func__);
				ret = -EINVAL;
				goto exit;
			}

			rtwusb->pipe_interrupt = num;
		}

		if (usb_endpoint_dir_out(endpoint) &&
		    usb_endpoint_xfer_bulk(endpoint)) {
			dev_dbg(dev, "%s: out endpoint num %i\n",
				__func__, num);
			if (j >= RTW_USB_MAX_EP_OUT_NUM ) {
				dev_warn(dev,
					 "%s: Too many OUT pipes\n", __func__);
				ret = -EINVAL;
				goto exit;
			}

			/* for out enpoint, address == number */
			rtwusb->out_ep[j++] = num;
			rtwusb->num_out_pipes++;
		}
	}

	switch (usbd->speed) {
	case USB_SPEED_LOW:
		pr_info("USB_SPEED_LOW\n");
		rtwusb->usb_speed = RTW_USB_SPEED_1_1;
		break;
	case USB_SPEED_FULL:
		pr_info("USB_SPEED_FULL\n");
		rtwusb->usb_speed = RTW_USB_SPEED_1_1;
		break;
	case USB_SPEED_HIGH:
		pr_info("USB_SPEED_HIGH\n");
		rtwusb->usb_speed = RTW_USB_SPEED_2;
		break;
	case USB_SPEED_SUPER:
		pr_info("USB_SPEED_SUPER\n");
		rtwusb->usb_speed = RTW_USB_SPEED_3;
		break;
	default:
		pr_info("USB speed unknown\n");
		break;
	}

exit:
	return ret;
}

static void rtw_usb_interface_configure(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	if (RTW_USB_IS_SUPER_SPEED(rtwusb))
		rtwusb->bulkout_size = RTW_USB_SUPER_SPEED_BULK_SIZE;
	else if (RTW_USB_IS_HIGH_SPEED(rtwusb))
		rtwusb->bulkout_size = RTW_USB_HIGH_SPEED_BULK_SIZE;
	else
		rtwusb->bulkout_size = RTW_USB_FULL_SPEED_BULK_SIZE;

	pr_info("%s : bulkout_size: %d\n", __func__, rtwusb->bulkout_size);
}

static void rtw_usb_tx_handler(struct work_struct *work)
{
	struct rtw_usb_work_data *work_data = container_of(work,
						       struct rtw_usb_work_data,
						       work);
	struct rtw89_dev *rtwdev = work_data->rtwdev;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct sk_buff *skb;
	int index;

	index = RTW89_DMA_CH_NUM - 1;
	while (index >= 0) {
		skb = skb_dequeue(&rtwusb->tx_queue[index]);
		if (skb)
			rtw_usb_tx_agg(rtwusb, skb);
		else
			index--;
	}
}

static void rtw_usb_indicate_tx_status(struct rtw89_dev *rtwdev,
				       struct sk_buff *skb)
{
	struct ieee80211_hw *hw = rtwdev->hw;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	info->flags |= IEEE80211_TX_STAT_ACK;

	ieee80211_tx_info_clear_status(info);
	ieee80211_tx_status_irqsafe(hw, skb);
}

static void rtw_usb_write_port_direct_complete(struct urb *urb)
{
	struct sk_buff *skb;

	skb = (struct sk_buff *)urb->context;
	dev_kfree_skb(skb);
	usb_free_urb(urb);
}
static int rtw_usb_write_port_direct(struct rtw89_dev *rtwdev, u8 addr, u32 cnt,
			      struct sk_buff *skb)
{
	int ret = -EINVAL;

	return ret;
#if 0
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *usbd = rtwusb->udev;
	struct urb *urb;
	unsigned int pipe;
	int ret;

	pipe = rtw_usb_get_pipe(rtwusb, addr);

	urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!urb)
		return -ENOMEM;

	usb_fill_bulk_urb(urb, usbd, pipe, skb->data, (int)cnt,
			  rtw_usb_write_port_direct_complete, skb);

	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (unlikely(ret))
		usb_free_urb(urb);

	return ret;
#endif
}
static int rtw_usb_write_port_wait(struct rtw89_dev *rtwdev, u8 addr, u32 cnt,
				   struct sk_buff *skb)
{
	int ret = -EINVAL;

	return ret;
#if 0
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *usbd = rtwusb->udev;
	unsigned int pipe;
	int ret;
	int transfer;

	pipe = rtw_usb_get_pipe(rtwusb, addr);

	ret = usb_bulk_msg(usbd, pipe, (void *)skb->data, (int)cnt,
			   &transfer, USB_MSG_TIMEOUT);
	if (ret < 0)
		rtw89_err(rtwdev, "failed to do USB bulk out, ret=%d\n", ret);

	return ret;
#endif
}

static void rtw_usb_tx_queue_init(struct rtw_usb *rtwusb)
{
	int i;

	for (i = 0; i < RTW89_DMA_CH_NUM; i++)
		skb_queue_head_init(&rtwusb->tx_queue[i]);

	skb_queue_head_init(&rtwusb->tx_ack_queue);
}

static void rtw_usb_tx_queue_purge(struct rtw_usb *rtwusb)
{
	int i;

	for (i = 0; i < RTW89_DMA_CH_NUM; i++)
		skb_queue_purge(&rtwusb->tx_queue[i]);

	skb_queue_purge(&rtwusb->tx_ack_queue);
}

static void rtw_usb_rx_queue_purge(struct rtw_usb *rtwusb)
{
	skb_queue_purge(&rtwusb->rx_queue);
}

static void rtw_usb_tx_ack_enqueue(struct rtw_usb *rtwusb,
				      struct sk_buff *skb)
{
	skb_queue_tail(&rtwusb->tx_ack_queue, skb);
}

static void rtw_usb_do_tx_ack_queue(struct rtw_usb *rtwusb)
{
	pr_info("TODO: %s\n", __func__);
#if 0
	struct rtw89_dev *rtwdev = rtwusb->rtwdev;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&rtwusb->tx_ack_queue))) {
		if (queue <= RTW_TX_QUEUE_VO)
			rtw_usb_indicate_tx_status(rtwdev, skb);
		else
			dev_kfree_skb(skb);
	}
#endif
}

static void rtw_usb_tx_agg_skb(struct rtw_usb *rtwusb,
			       struct sk_buff_head *list,
			       struct sk_buff *skb_head, struct sk_buff *skb)
{
	pr_info("TODO: %s\n", __func__);
#if 0
	struct sk_buff *skb_iter;
	unsigned long flags;
	u8 *data_ptr;
	int agg_num = 0, len, max_len;

	data_ptr = skb_head->data;
	skb_iter = skb;
	while (skb_iter) {
		memcpy(data_ptr, skb_iter->data, skb_iter->len);
		len = ALIGN(skb_iter->len, 8);
		skb_put(skb_head, len);
		data_ptr += len;
		agg_num++;

		rtw_usb_tx_ack_enqueue(rtwusb, skb_iter);

		spin_lock_irqsave(&list->lock, flags);
		skb_iter = skb_peek(list);
		max_len = RTW_USB_MAX_XMITBUF_SZ - skb_head->len;
		if (skb_iter && skb_iter->len < max_len)
			__skb_unlink(skb_iter, list);
		else
			skb_iter = NULL;
		spin_unlock_irqrestore(&list->lock, flags);
	}

	if (agg_num > 1)
		rtw_usb_fill_tx_checksum(rtwusb, skb_head, agg_num);
#endif
}

static struct sk_buff *rtw_usb_tx_agg_check(struct rtw_usb *rtwusb,
					    struct sk_buff *skb,
					    u8 queue)
{
	pr_info("TODO: %s\n", __func__);
	return NULL;
#if 0
	struct sk_buff_head *list;
	struct sk_buff *skb_head;

	if (queue != RTW_TX_QUEUE_VO)
		return NULL;

	list = &rtwusb->tx_queue[queue];
	if (skb_queue_empty(list))
		return NULL;

	skb_head = dev_alloc_skb(RTW_USB_MAX_XMITBUF_SZ);
	if (!skb_head)
		return NULL;

	rtw_usb_tx_agg_skb(rtwusb, list, skb_head, skb);
	return skb_head;
#endif
}

static void rtw_usb_tx_agg(struct rtw_usb *rtwusb, struct sk_buff *skb)
{
	pr_info("TODO: %s\n", __func__);
#if 0
	struct rtw89_dev *rtwdev = rtwusb->rtwdev;
	struct sk_buff *skb_head;
	int ret;
	u8 queue, qsel;

	qsel = GET_TX_DESC_QSEL(skb->data);
	queue = rtw_tx_qsel_to_queue(qsel);

	skb_head = rtw_usb_tx_agg_check(rtwusb, skb, queue);

	if (!skb_head) {
		skb_head = skb;
		rtw_usb_tx_ack_enqueue(rtwusb, skb);
	}

	ret = rtw_usb_write_port_wait(rtwdev, queue, skb_head->len, skb_head);
	if (ret)
		rtw89_err(rtwdev, "failed to do USB write sync, ret=%d\n", ret);

	if (skb_head != skb)
		dev_kfree_skb(skb_head);

	rtw_usb_do_tx_ack_queue(rtwusb);
#endif
}

static int rtw_usb_write_data(struct rtw89_dev *rtwdev,
			      struct rtw_tx_pkt_info *pkt_info,
			      u8 *buf)
{
#if 0
	struct rtw_chip_info *chip = rtwdev->chip;
	struct sk_buff *skb;
	unsigned int desclen, len, headsize, size;
	u8 queue, qsel;
	int ret = 0;

	size = pkt_info->tx_pkt_size;
	qsel = pkt_info->qsel;
	desclen = chip->tx_pkt_desc_sz;
	headsize = (pkt_info->offset) ? pkt_info->offset : desclen;
	len = headsize + size;

	skb = dev_alloc_skb(len);
	if (unlikely(!skb))
		return -ENOMEM;

	skb_reserve(skb, headsize);
	skb_put_data(skb, buf, size);
	skb_push(skb, headsize);
	memset(skb->data, 0, headsize);
	rtw_tx_fill_tx_desc(pkt_info, skb);
	chip->ops->fill_txdesc_checksum(rtwdev, pkt_info, skb->data);
	queue = rtw_tx_qsel_to_queue(qsel);

	ret = rtw_usb_write_port_direct(rtwdev, queue, len, skb);
	if (unlikely(ret))
		rtw89_err(rtwdev, "failed to do USB write async, ret=%d\n",
			ret);

	return ret;
#endif
	return -EIO;
}

static int rtw_usb_write_data_rsvd_page(struct rtw89_dev *rtwdev, u8 *buf,
					u32 size)
{
	int ret = -EINVAL;

	pr_info("%s ==>\n", __func__);
	return ret;
#if 0
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_usb *rtwusb;
	struct rtw_tx_pkt_info pkt_info = {0};
	u32 len, desclen;
	u8 qsel = TX_DESC_QSEL_BEACON;

	if (unlikely(!rtwdev))
		return -EINVAL;

	rtwusb = rtw_get_usb_priv(rtwdev);
	if (unlikely(!rtwusb))
		return -EINVAL;

	pkt_info.tx_pkt_size = size;
	pkt_info.qsel = qsel;

	desclen = chip->tx_pkt_desc_sz;
	len = desclen + size;
	if (len % rtwusb->bulkout_size == 0) {
		len = len + RTW_USB_PACKET_OFFSET_SZ;
		pkt_info.offset = desclen + RTW_USB_PACKET_OFFSET_SZ;
		pkt_info.pkt_offset = 1;
	} else {
		pkt_info.offset = desclen;
	}

	return rtw_usb_write_data(rtwdev, &pkt_info, buf);
	return rtw_usb_write_data(rtwdev, buf, size, TX_DESC_QSEL_BEACON);
#endif
}

static int rtw_usb_write_data_h2c(struct rtw89_dev *rtwdev, u8 *buf, u32 size)
{
	int ret = -EINVAL;

	pr_info("%s ==>\n", __func__);
	return ret;
#if 0
	return rtw_usb_write_data(rtwdev, buf, size, TX_DESC_QSEL_H2C);
#endif
}

static int rtw_usb_tx_write(struct rtw_dev *rtwdev,
			    struct rtw_tx_pkt_info *pkt_info,
			    struct sk_buff *skb)
{
	int ret = -EINVAL;

	pr_info("%s ==>\n", __func__);
	return ret;
#if 0
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_usb_tx_data *tx_data;
	u8 *pkt_desc;
	u8 queue = rtw_usb_tx_queue_mapping(skb);

	if (!pkt_info)
		return -EINVAL;

	pkt_desc = skb_push(skb, chip->tx_pkt_desc_sz);
	memset(pkt_desc, 0, chip->tx_pkt_desc_sz);
	pkt_info->qsel = rtw_tx_queue_to_qsel(skb, queue);
	rtw_tx_fill_tx_desc(pkt_info, skb);

	chip->ops->fill_txdesc_checksum(rtwdev, pkt_info, skb->data);

	tx_data = rtw_usb_get_tx_data(skb);
	tx_data->sn = pkt_info->sn;

	skb_queue_tail(&rtwusb->tx_queue[queue], skb);
	return 0;
#endif
}

static void rtw_usb_tx_kick_off(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	queue_work(rtwusb->txwq, &rtwusb->tx_handler_data->work);
}

static void rtw_usb_rx_handler(struct work_struct *work)
{
	pr_info("%s ==>\n", __func__);
#if 0
	struct rtw_usb_work_data *work_data = container_of(work,
						struct rtw_usb_work_data,
						work);
	struct rtw89_dev *rtwdev = work_data->rtwdev;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_rx_pkt_stat pkt_stat;
	struct ieee80211_rx_status rx_status;
	struct sk_buff *skb;
	u32 pkt_desc_sz = chip->rx_pkt_desc_sz;
	u32 pkt_offset;
	u8 *rx_desc;

	while ((skb = skb_dequeue(&rtwusb->rx_queue)) != NULL) {
			rx_desc = skb->data;
			chip->ops->query_rx_desc(rtwdev, rx_desc, &pkt_stat,
						 &rx_status);

			pkt_offset = pkt_desc_sz + pkt_stat.drv_info_sz +
				     pkt_stat.shift;

			if (pkt_stat.is_c2h) {
				skb_put(skb, pkt_stat.pkt_len + pkt_offset);
				rtw_fw_c2h_cmd_rx_irqsafe(rtwdev, pkt_offset,
							  skb);
				continue;
			}

			if (skb_queue_len(&rtwusb->rx_queue) >= 64) {
				rtw89_err(rtwdev, "rx_queue overflow\n");
				dev_kfree_skb(skb);
				continue;
			}

			skb_put(skb, pkt_stat.pkt_len);
			skb_reserve(skb, pkt_offset);

			memcpy(skb->cb, &rx_status, sizeof(rx_status));
			ieee80211_rx_irqsafe(rtwdev->hw, skb);
	}
#endif
}

static void rtw_usb_read_port_complete(struct urb *urb)
{
	struct rx_usb_ctrl_block *rxcb = urb->context;
	struct rtw89_dev *rtwdev = (struct rtw89_dev *)rxcb->data;
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct sk_buff *skb = rxcb->rx_skb;

	if (urb->status == 0) {
		if (urb->actual_length >= RTW_USB_MAX_RECVBUF_SZ ||
		    urb->actual_length < 24) {
			rtw89_err(rtwdev, "actual_size error:%d\n",
				urb->actual_length);
			if (skb)
				dev_kfree_skb(skb);
		} else {
			skb_queue_tail(&rtwusb->rx_queue, skb);
			queue_work(rtwusb->rxwq,
				   &rtwusb->rx_handler_data->work);
		}

		rtw_usb_read_port(rtwdev, RTW_USB_BULK_IN_ADDR, rxcb);
	} else {
		pr_info("###=> %s status(%d)\n", __func__, urb->status);

		switch (urb->status) {
		case -EINVAL:
		case -EPIPE:
		case -ENODEV:
		case -ESHUTDOWN:
		case -ENOENT:
		case -EPROTO:
		case -EILSEQ:
		case -ETIME:
		case -ECOMM:
		case -EOVERFLOW:
		case -EINPROGRESS:
			pr_info("%s: Error USB is in progress\n", __func__);
			break;
		default:
			rtw89_err(rtwdev, "status unknown=%d\n", urb->status);
			break;
		}
		if (skb)
			dev_kfree_skb(skb);
	}
}

static void rtw_usb_read_port(struct rtw89_dev *rtwdev, u8 addr,
			      struct rx_usb_ctrl_block *rxcb)
{
	pr_info("TODO: %s \n", __func__);
#if 0
	struct urb *urb = NULL;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *usbd = rtwusb->udev;
	struct sk_buff *skb;
	unsigned int pipe;
	size_t alignment;
	u32 len;

	int ret;

	urb = rxcb->rx_urb;
	rxcb->data = (void *)rtwdev;

	pipe = rtw_usb_get_pipe(rtwusb, RTW_USB_BULK_IN_ADDR);

	len = RTW_USB_MAX_RECVBUF_SZ + RTW_USB_RECVBUFF_ALIGN_SZ;
	skb = dev_alloc_skb(len);
	if (!skb) {
		pr_err("%s : dev_alloc_skb failed\n", __func__);
		return -ENOMEM;
	}
	alignment = (size_t)skb->data & (RTW_USB_RECVBUFF_ALIGN_SZ - 1);
	skb_reserve(skb, RTW_USB_RECVBUFF_ALIGN_SZ - alignment);

	urb->transfer_buffer = skb->data;
	rxcb->rx_skb = skb;

	usb_fill_bulk_urb(urb, usbd, pipe,
			  urb->transfer_buffer,
			  RTW_USB_MAX_RECVBUF_SZ,
			  rtw_usb_read_port_complete,
			  rxcb);

	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (ret)
		rtw89_err(rtwdev, "failed to submit USB urb, ret=%d\n", ret);
#endif
}

static void rtw_usb_inirp_init(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rx_usb_ctrl_block *rxcb;
	int i;

	pr_info("%s ===>\n", __func__);


	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		rxcb->rx_urb = NULL;
	}

	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		rxcb->rx_urb = usb_alloc_urb(0, GFP_KERNEL);
		if (!rxcb->rx_urb) {
			pr_err("%s: usb_alloc_urb failed\n", __func__);
			goto err_exit;
		}
		rtw_usb_read_port(rtwdev, RTW_USB_BULK_IN_ADDR, rxcb);
	}

	return;

err_exit:
	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		if (rxcb->rx_urb)
			usb_kill_urb(rxcb->rx_urb);
	}
}

static void rtw_usb_inirp_deinit(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rx_usb_ctrl_block *rxcb;
	int i;

	pr_info("%s ===>\n", __func__);

	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		if (rxcb->rx_urb)
			usb_kill_urb(rxcb->rx_urb);
	}
}

/* struct usb_driver relative functions */
static int rtw89_usb_ops_tx(struct rtw89_dev *rtwdev,
			    struct rtw89_core_tx_request *tx_req)
{
	pr_info("%s ====>\n", __func__);
#if 0
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_usb_tx_data *tx_data;
	u8 *pkt_desc;

	if (!pkt_info)
		return -EINVAL;

	pkt_desc = skb_push(skb, chip->tx_pkt_desc_sz);
	memset(pkt_desc, 0, chip->tx_pkt_desc_sz);
	pkt_info->qsel = rtw_queue_to_qsel(skb, queue);
	rtw_tx_fill_tx_desc(pkt_info, skb);

	chip->ops->fill_txdesc_checksum(rtwdev, pkt_info, skb->data);

	tx_data = rtw_usb_get_tx_data(skb);
	tx_data->sn = pkt_info->sn;

	skb_queue_tail(&rtwusb->tx_queue[queue], skb);
#endif
	return 0;
}

static void rtw89_usb_ops_reset(struct rtw89_dev *rtwdev)
{
	pr_info("TODO: %s ====>\n", __func__);
}

static int rtw89_usb_ops_mac_pre_init(struct rtw89_dev *rtwdev)
{
	pr_info("TODO: %s ====>\n", __func__);

	return 0;
}

static int rtw89_usb_ops_mac_post_init(struct rtw89_dev *rtwdev)
{
	pr_info("TODO: %s ====>\n", __func__);

	return 0;
}



static struct rtw89_hci_ops rtw89_usb_ops = {
	.tx = rtw89_usb_ops_tx,
	.reset = rtw89_usb_ops_reset,

	.read8 = rtw_usb_read8,
	.read16 = rtw_usb_read16,
	.read32 = rtw_usb_read32,
	.write8 = rtw_usb_write8,
	.write16 = rtw_usb_write16,
	.write32 = rtw_usb_write32,

	.mac_pre_init = rtw89_usb_ops_mac_pre_init,
	.mac_post_init = rtw89_usb_ops_mac_post_init,
#if 0
	.write_data_rsvd_page = rtw_usb_write_data_rsvd_page,
	.write_data_h2c = rtw_usb_write_data_h2c,
#endif
};

static int rtw_usb_init_rx(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->rxwq = create_singlethread_workqueue("rtw89_usb: rx wq");
	if (!rtwusb->rxwq) {
		rtw89_err(rtwdev, "failed to create RX work queue\n");
		return -ENOMEM;
	}

	skb_queue_head_init(&rtwusb->rx_queue);

	rtwusb->rx_handler_data = kmalloc(sizeof(*rtwusb->rx_handler_data),
					  GFP_KERNEL);
	if (!rtwusb->rx_handler_data)
		goto err_destroy_wq;

	rtwusb->rx_handler_data->rtwdev = rtwdev;

	INIT_WORK(&rtwusb->rx_handler_data->work, rtw_usb_rx_handler);

	return 0;

err_destroy_wq:
	destroy_workqueue(rtwusb->rxwq);
	return -ENOMEM;
}

static void rtw_usb_deinit_rx(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtw_usb_rx_queue_purge(rtwusb);
	flush_workqueue(rtwusb->rxwq);
	destroy_workqueue(rtwusb->rxwq);
	kfree(rtwusb->rx_handler_data);
}

static int rtw_usb_init_tx(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->txwq = create_singlethread_workqueue("rtw88_usb: tx wq");
	if (!rtwusb->txwq) {
		rtw89_err(rtwdev, "failed to create TX work queue\n");
		return -ENOMEM;
	}

	rtw_usb_tx_queue_init(rtwusb);

	rtwusb->tx_handler_data = kmalloc(sizeof(*rtwusb->tx_handler_data),
					  GFP_KERNEL);
	if (!rtwusb->tx_handler_data)
		goto err_destroy_wq;

	rtwusb->tx_handler_data->rtwdev = rtwdev;

	INIT_WORK(&rtwusb->tx_handler_data->work, rtw_usb_tx_handler);

	return 0;

err_destroy_wq:
	destroy_workqueue(rtwusb->txwq);
	return -ENOMEM;
}

static void rtw_usb_deinit_tx(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtw_usb_tx_queue_purge(rtwusb);
	flush_workqueue(rtwusb->txwq);
	destroy_workqueue(rtwusb->txwq);
	kfree(rtwusb->tx_handler_data);
}

static int rtw_usb_intf_init(struct rtw89_dev *rtwdev,
			     struct usb_interface *intf)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *udev = usb_get_dev(interface_to_usbdev(intf));
	int ret;

	rtwusb->udev = udev;
	rtwusb->rtwdev = rtwdev;
	ret = rtw_usb_parse(rtwdev, intf);
	if (ret) {
		rtw89_err(rtwdev, "failed to check USB configuration, ret=%d\n",
			ret);
		return ret;
	}

	usb_set_intfdata(intf, rtwdev->hw);
	rtw_usb_interface_configure(rtwdev);
	SET_IEEE80211_DEV(rtwdev->hw, &intf->dev);
	mutex_init(&rtwusb->usb_buf_mutex);

	return 0;
}

static void rtw_usb_intf_deinit(struct rtw89_dev *rtwdev,
				struct usb_interface *intf)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	usb_put_dev(rtwusb->udev);
	usb_set_intfdata(intf, NULL);
	mutex_destroy(&rtwusb->usb_buf_mutex);
}

int rtw_usb_probe(struct usb_interface *intf,
			 const struct usb_device_id *id)
{
	struct rtw89_dev *rtwdev;
	struct rtw_usb *rtwusb;
	struct ieee80211_hw *hw;
	int drv_data_size;
	int ret = -EINVAL;

	drv_data_size = sizeof(struct rtw89_dev) + sizeof(struct rtw_usb);
	hw = ieee80211_alloc_hw(drv_data_size, &rtw89_ops);
	if (!hw)
		return -ENOMEM;

	rtwdev = hw->priv;
	rtwdev->hw = hw;
	rtwdev->dev = &intf->dev;

	switch (id->driver_info) {
	case RTL8852A:
		rtwdev->chip = &rtw8852a_chip_info;
		break;
	default:
		ret = -ENOENT;
		goto err_release_hw;
	}
	rtwdev->hci.ops = &rtw89_usb_ops;
	rtwdev->hci.type = RTW89_HCI_TYPE_USB;

	ret = rtw_usb_intf_init(rtwdev, intf);
	if (ret) {
		rtw89_err(rtwdev, "failed to init USB interface\n");
		goto err_release_hw;
	}

	ret = rtw_usb_init_tx(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to init USB TX\n");
		goto err_destroy_usb;
	}

	ret = rtw_usb_init_rx(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to init USB RX\n");
		goto err_destroy_txwq;
	}

	ret = rtw89_core_register(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to register core\n");
		goto err_destroy_rxwq;
	}

	return 0;

err_destroy_rxwq:
	rtw_usb_deinit_rx(rtwdev);

err_destroy_txwq:
	rtw_usb_deinit_tx(rtwdev);

err_destroy_usb:
	rtw_usb_intf_deinit(rtwdev, intf);

err_release_hw:
	ieee80211_free_hw(hw);

	return ret;
}
EXPORT_SYMBOL(rtw_usb_probe);

void rtw_usb_disconnect(struct usb_interface *intf)
{
	struct ieee80211_hw *hw = usb_get_intfdata(intf);
	struct rtw89_dev *rtwdev;
	struct rtw_usb *rtwusb;

	if (!hw)
		return;

	rtwdev = hw->priv;
	rtwusb = rtw_get_usb_priv(rtwdev);

	rtw89_core_unregister(rtwdev);
	rtw_usb_deinit_rx(rtwdev);
	rtw_usb_deinit_tx(rtwdev);
	if (rtwusb->udev->state != USB_STATE_NOTATTACHED) {
		pr_info("Device still attached, trying to reset\n");
		usb_reset_device(rtwusb->udev);
	}

	rtw_usb_intf_deinit(rtwdev, intf);
	ieee80211_free_hw(hw);
}
EXPORT_SYMBOL(rtw_usb_disconnect);

static const struct usb_device_id rtw_usb_id_table[] = {
	{ RTK_USB_DEVICE_AND_INTERFACE(RTW_USB_VENDOR_ID_REALTEK,
				       RTW_USB_PRODUCT_ID_REALTEK_8852A,
				       0xff, 0xff, 0xff,
				       RTL8852A) },
	{},
};
MODULE_DEVICE_TABLE(usb, rtw_usb_id_table);

static struct usb_driver rtw89_usb_driver = {
	.name = "rtw89_usb",
	.id_table = rtw_usb_id_table,
	.probe = rtw_usb_probe,
	.disconnect = rtw_usb_disconnect,
};

module_usb_driver(rtw89_usb_driver);

MODULE_AUTHOR("Realtek Corporation");
MODULE_DESCRIPTION("Realtek 802.11ax wireless USB driver");
MODULE_LICENSE("Dual BSD/GPL");
