// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include <linux/module.h>
#include <linux/usb.h>
#include <linux/mutex.h>
#include "core.h"
#include "debug.h"
#include "usb.h"

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
			      addr, 0, &rtwusb->usb_buf.val8, sizeof(u8),
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
			      addr, 0, &rtwusb->usb_buf.val16, sizeof(u16),
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
			      addr, 0, &rtwusb->usb_buf.val32, sizeof(u32),
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
			      addr, 0, &rtwusb->usb_buf.val8, sizeof(u8),
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
			      addr, 0, &rtwusb->usb_buf.val16, sizeof(u16),
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
			      addr, 0, &rtwusb->usb_buf.val32, sizeof(u32),
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
	rtwusb->nr_out_eps = j;
	pr_info("out eps num: %d\n", rtwusb->nr_out_eps);
	return ret;
}

static void usb_interface_configure(struct rtw89_dev *rtwdev)
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

/*
 * driver status relative functions
 */

static
bool rtw_usb_is_bus_ready(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	return (atomic_read(&rtwusb->is_bus_drv_ready) == true);
}

static
void rtw_usb_set_bus_ready(struct rtw89_dev *rtwdev, bool ready)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	atomic_set(&rtwusb->is_bus_drv_ready, ready);
}

/* RTW Thread functions */

static int rtw_init_event(struct rtw_event *event)
{
	atomic_set(&event->event_condition, 1);
	init_waitqueue_head(&event->event_queue);
	return 0;
}

static int rtw_wait_event(struct rtw_event *event, u32 timeout)
{
	int status = 0;

	if (!timeout)
		status = wait_event_interruptible(event->event_queue,
				(atomic_read(&event->event_condition) == 0));
	else
		status = wait_event_interruptible_timeout(event->event_queue,
				(atomic_read(&event->event_condition) == 0),
				timeout);
	return status;
}

static void rtw_set_event(struct rtw_event *event)
{
	atomic_set(&event->event_condition, 0);
	wake_up_interruptible(&event->event_queue);
}

static void rtw_reset_event(struct rtw_event *event)
{
	atomic_set(&event->event_condition, 1);
}

static void rtw_create_handler(struct rtw_handler *handler)
{
	atomic_set(&handler->handler_done, 0);
}

static void rtw_kill_handler(struct rtw_handler *handler)
{
	atomic_inc(&handler->handler_done);
	rtw_set_event(&handler->event);
}

// TX functions

void rtw_tx_func(struct rtw_usb *rtwusb);
static void rtw_usb_tx_handler(struct work_struct *work)
{
	struct rtw_work_data *my_data = container_of(work, struct rtw_work_data,
						 work);
	struct rtw89_dev *rtwdev = my_data->rtwdev;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	u32 timeout = 0;

	do {
		rtw_wait_event(&rtwusb->tx_handler.event, timeout);
		rtw_reset_event(&rtwusb->tx_handler.event);

		if (rtwusb->init_done)
			rtw_tx_func(rtwusb);
	} while (atomic_read(&rtwusb->tx_handler.handler_done) == 0);
}

static void rtw_indicate_tx_status(struct rtw89_dev *rtwdev, struct sk_buff *skb)
{
	struct ieee80211_hw *hw = rtwdev->hw;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	info->flags |= IEEE80211_TX_STAT_ACK;

	ieee80211_tx_info_clear_status(info);
	ieee80211_tx_status_irqsafe(hw, skb);
}

static u32 rtw_usb_write_port(struct rtw89_dev *rtwdev, u8 addr, u32 cnt,
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
		pr_err("usb_bulk_msg error, ret=%d\n", ret);

	return ret;
#endif
}

static inline void rtw_tx_queue_init(struct rtw_usb *rtwusb)
{
	int i;

	for (i = 0; i < RTW89_DMA_CH_NUM; i++)
		skb_queue_head_init(&rtwusb->tx_queue[i]);

	skb_queue_head_init(&rtwusb->tx_ack_queue);
}

static inline void rtw_tx_queue_purge(struct rtw_usb *rtwusb)
{
	int i;

	for (i = 0; i < RTW89_DMA_CH_NUM; i++)
		skb_queue_purge(&rtwusb->tx_queue[i]);

	skb_queue_purge(&rtwusb->tx_ack_queue);
}

static struct sk_buff *rtw_usb_tx_dequeue(struct rtw_usb *rtwusb)
{
	struct sk_buff *skb = NULL;
	static int index = RTW89_DMA_CH_NUM - 1;

	for (; index >= 0; index--) {
		skb = skb_dequeue(&rtwusb->tx_queue[index]);
		if (skb)
			break;
	}

	if (index < 0)
		index = RTW89_DMA_CH_NUM - 1;

	return skb;
}

static inline void rtw_tx_ack_enqueue(struct rtw_usb *rtwusb,
				      struct sk_buff *skb)
{
	skb_queue_tail(&rtwusb->tx_ack_queue, skb);
}

static inline void rtw_do_tx_ack_queue(struct rtw_usb *rtwusb)
{
	struct rtw89_dev *rtwdev = rtwusb->rtwdev;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&rtwusb->tx_ack_queue))) {
		rtw_indicate_tx_status(rtwdev, skb);
	}
}

static inline void rtw_usb_tx_agg(struct rtw_usb *rtwusb, struct sk_buff *skb,
				  u8 queue)
{
	struct rtw89_dev *rtwdev = rtwusb->rtwdev;
	int status;

	rtw_tx_ack_enqueue(rtwusb, skb);

	status = rtw_usb_write_port(rtwdev, queue, skb->len, skb);
	if (status) {
		pr_err("%s, rtw_usb_write_xmit failed, ret=%d\n",
		       __func__, status);
	}

	rtw_do_tx_ack_queue(rtwusb);
}

void rtw_tx_func(struct rtw_usb *rtwusb)
{
	struct sk_buff *skb;

	while (1) {
		mutex_lock(&rtwusb->tx_lock);

		skb = rtw_usb_tx_dequeue(rtwusb);
		if (!skb) {
			mutex_unlock(&rtwusb->tx_lock);
			break;
		}

		pr_info("%s ==>\n", __func__);

		mutex_unlock(&rtwusb->tx_lock);
	}
}

static int
rtw_usb_write_data(struct rtw89_dev *rtwdev, u8 *buf, u32 size, u8 qsel)
{

#if 0
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct sk_buff *skb;
	struct rtw_tx_pkt_info pkt_info;
	u32 desclen, len, headsize;
	u8 ret = 0;
	u8 addr;

	if (!rtwusb) {
		pr_err("%s: rtwusb is NULL\n", __func__);
		return -EINVAL;
	}

	desclen = rtwusb->txdesc_size;
	len = desclen + size;
	headsize = desclen;

	skb = NULL;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.tx_pkt_size = size;
	pkt_info.qsel = qsel;
	if (qsel == TX_DESC_QSEL_BEACON) {
		if (rtwusb->bulkout_size == 0) {
			rtw_err(rtwdev, "%s: ERROR: bulkout_size is 0\n",
				__func__);
			return -EINVAL;
		}
		if (len % rtwusb->bulkout_size == 0) {
			len = len + RTW_USB_PACKET_OFFSET_SZ;
			headsize = desclen + RTW_USB_PACKET_OFFSET_SZ;
			pkt_info.offset = desclen + RTW_USB_PACKET_OFFSET_SZ;
			pkt_info.pkt_offset = 1;
		} else {
			pkt_info.offset = desclen;
		}
	} else if (qsel == TX_DESC_QSEL_H2C) {
		;
	} else {
		rtw_err(rtwdev, "%s: qsel may be error(%d)\n", __func__, qsel);
		return -EINVAL;
	}

	skb = dev_alloc_skb(len);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, headsize);

	memcpy((u8 *)skb_put(skb, size), buf, size);

	skb_push(skb, headsize);
	memset(skb->data, 0, headsize);

	rtw_tx_fill_tx_desc(&pkt_info, skb);

	chip->ops->fill_txdesc_checksum(rtwdev, &pkt_info, skb->data);

	addr = rtw_qsel_to_queue(qsel);

	ret = rtw_usb_write_port(rtwdev, addr, len, skb);
	if (ret) {
		pr_err("%s ,rtw_usb_write_port failed, ret=%d\n",
		       __func__, ret);
		goto exit;
	}
	dev_kfree_skb(skb);

	return 0;

exit:
	dev_kfree_skb(skb);
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
	rtw_dbg(rtwdev, RTW_DBG_USB, "%s: enter\n", __func__);
	if (!rtwdev) {
		pr_err("%s: rtwdev is NULL\n", __func__);
		return -EINVAL;
	}
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


static void rtw_usb_tx_kick_off(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtw_set_event(&rtwusb->tx_handler.event);
}

// RX functions
//static u32 rtw_usb_read_port(struct rtw89_dev *rtwdev, u8 addr,
//			     struct rx_usb_ctrl_block *rxcb);

static void rtw_usb_rx_handler(struct work_struct *work)
{
	struct rtw_work_data *my_data = container_of(work, struct rtw_work_data,
						 work);
	struct rtw89_dev *rtwdev = my_data->rtwdev;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	u32 timeout = 0;
	struct sk_buff *skb;

	do {
		rtw_wait_event(&rtwusb->rx_handler.event, timeout);
		rtw_reset_event(&rtwusb->rx_handler.event);

		while (true) {
			if (atomic_read(&rtwusb->rx_handler.handler_done))
				goto out;

			skb = skb_dequeue(&rtwusb->rx_queue);
			if (!skb)
				break;

#if 0
			rx_desc = skb->data;
			chip->ops->query_rx_desc(rtwdev, rx_desc, &pkt_stat,
						 &rx_status);

			/* offset from rx_desc to payload */
			pkt_offset = pkt_desc_sz + pkt_stat.drv_info_sz +
				     pkt_stat.shift;

			if (pkt_stat.is_c2h) {
				skb_put(skb, pkt_stat.pkt_len + pkt_offset);
				*((u32 *)skb->cb) = pkt_offset;
				rtw_fw_c2h_cmd_handle(rtwdev, skb);
				dev_kfree_skb_any(skb);
				continue;
			}

			if (skb_queue_len(&rtwusb->rx_queue) >= 64) {
				pr_err("%s: rx_queue overflow\n", __func__);
				dev_kfree_skb_any(skb);
				continue;
			}

			skb_put(skb, pkt_stat.pkt_len);
			skb_reserve(skb, pkt_offset);

			memcpy(skb->cb, &rx_status, sizeof(rx_status));
			ieee80211_rx_irqsafe(rtwdev->hw, skb);
#endif
		}
	} while (1);

out:
	skb_queue_purge(&rtwusb->rx_queue);
}

#if 0
static void rtw_usb_read_port_complete(struct urb *urb)
{
	struct rx_usb_ctrl_block *rxcb = urb->context;
	struct rtw89_dev *rtwdev = (struct rtw89_dev *)rxcb->data;
	struct sk_buff *skb = rxcb->rx_skb;
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;

	if (urb->status == 0) {
		if (urb->actual_length >= RTW_USB_MAX_RECVBUF_SZ ||
		    urb->actual_length < 24) {
			pr_err("%s actual_size error:%d\n",
			       __func__, urb->actual_length);
			if (skb)
				dev_kfree_skb(skb);
		} else {
			skb_queue_tail(&rtwusb->rx_queue, skb);
			rtw_set_event(&rtwusb->rx_handler.event);
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
			rtw_usb_set_bus_ready(rtwdev, false);
			break;
		case -EPROTO:
		case -EILSEQ:
		case -ETIME:
		case -ECOMM:
		case -EOVERFLOW:
			break;
		case -EINPROGRESS:
			pr_info("%s: Error USB is in progress\n", __func__);
			break;
		default:
			pr_err("%s: unknown : status=%d\n", __func__,
			       urb->status);
			break;
		}
		if (skb)
			dev_kfree_skb(skb);
	}
}

static u32 rtw_usb_read_port(struct rtw89_dev *rtwdev, u8 addr,
			     struct rx_usb_ctrl_block *rxcb)
{
	unsigned int pipe;
	int ret = -1;
	struct urb *urb = NULL;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *usbd = rtwusb->udev;
	struct sk_buff *skb;
	u32 len;
	size_t buf_addr;
	size_t alignment = 0;

	if (!rtw_usb_is_bus_ready(rtwdev)) {
		pr_info("%s: cannot read USB port\n", __func__);
		return 0;
	}

	urb = rxcb->rx_urb;
	rxcb->data = (u8 *)rtwdev;

	pipe = rtw_usb_get_pipe(rtwusb, RTW_USB_BULK_IN_ADDR);

	len = RTW_USB_MAX_RECVBUF_SZ + RTW_USB_RECVBUFF_ALIGN_SZ;
	skb = dev_alloc_skb(len);
	if (!skb) {
		pr_err("%s : dev_alloc_skb failed\n", __func__);
		return -ENOMEM;
	}
	buf_addr = (size_t)skb->data;
	alignment = buf_addr & (RTW_USB_RECVBUFF_ALIGN_SZ - 1);
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
		pr_err("%s: usb_submit_urb failed, ret=%d\n", __func__, ret);

	return ret;
}

static void rtw_usb_inirp_init(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rx_usb_ctrl_block *rxcb;
	int i;

	pr_info("%s ===>\n", __func__);

	rtw_usb_set_bus_ready(rtwdev, true);

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
	rtw_usb_set_bus_ready(rtwdev, false);

	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		if (rxcb->rx_urb)
			usb_kill_urb(rxcb->rx_urb);
	}
}
#endif

/* struct usb_driver relative functions */

static int rtw_usb_init_rx(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->rxwq = create_singlethread_workqueue("rtw88: TX work queue");
	if (!rtwusb->rxwq) {
		pr_err("%s: create_singlethread_workqueue failed\n", __func__);
		goto err;
	}

	skb_queue_head_init(&rtwusb->rx_queue);
	rtw_create_handler(&rtwusb->rx_handler);
	rtw_init_event(&rtwusb->rx_handler.event);

	rtwusb->rx_handler_data = kmalloc(sizeof(*rtwusb->rx_handler_data),
					  GFP_KERNEL);
	if (!rtwusb->rx_handler_data)
		goto err_destroy_wq;

	rtwusb->rx_handler_data->rtwdev = rtwdev;

	INIT_WORK(&rtwusb->rx_handler_data->work, rtw_usb_rx_handler);
	queue_work(rtwusb->rxwq, &rtwusb->rx_handler_data->work);

	return 0;

err_destroy_wq:
	flush_workqueue(rtwusb->rxwq);
	destroy_workqueue(rtwusb->rxwq);

err:
	return -ENOMEM;
}

static int rtw_usb_init_tx(struct rtw89_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->txwq = create_singlethread_workqueue("rtw88: TX work queue");
	if (!rtwusb->txwq) {
		pr_err("%s: create_singlethread_workqueue failed\n", __func__);
		goto err;
	}

	rtw_tx_queue_init(rtwusb);

	rtw_create_handler(&rtwusb->tx_handler);
	rtw_init_event(&rtwusb->tx_handler.event);

	rtwusb->tx_handler_data = kmalloc(sizeof(*rtwusb->tx_handler_data),
					  GFP_KERNEL);
	if (!rtwusb->tx_handler_data)
		goto err_destroy_wq;

	rtwusb->tx_handler_data->rtwdev = rtwdev;

	INIT_WORK(&rtwusb->tx_handler_data->work, rtw_usb_tx_handler);
	queue_work(rtwusb->txwq, &rtwusb->tx_handler_data->work);

	return 0;

err_destroy_wq:
	flush_workqueue(rtwusb->txwq);
	destroy_workqueue(rtwusb->txwq);

err:
	return -ENOMEM;
}

static int rtw_os_alloc_hw(struct rtw89_dev **prtwdev,
			    const struct usb_device_id *id)
{
	struct ieee80211_hw *hw;
	struct rtw89_dev *rtwdev;
	struct rtw_usb *rtwusb;
	int drv_data_size;
	int ret;

	*prtwdev = NULL;

	drv_data_size = sizeof(struct rtw89_dev) + sizeof(struct rtw_usb);
	hw = ieee80211_alloc_hw(drv_data_size, &rtw89_ops);
	if (!hw) {
		pr_err("ieee80211_alloc_hw: No memory for device\n");
		ret = -ENOMEM;
		goto finish;
	}

	rtwdev = hw->priv;
	rtwdev->hw = hw;

	switch (id->driver_info) {
	case RTL8852A:
		rtwdev->chip = &rtw8852a_chip_info;
		break;
	default:
		ret = -ENOENT;
		goto err_release_hw;
	}

	rtwusb = rtw_get_usb_priv(rtwdev);
	rtwusb->rtwdev = rtwdev;

	*prtwdev = rtwdev;
	return 0;

err_release_hw:
	ieee80211_free_hw(hw);

finish:
	return ret;
}

static void rtw_os_free_hw(struct rtw89_dev *rtwdev)
{
	struct ieee80211_hw *hw = rtwdev->hw;

	ieee80211_free_hw(hw);
}

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
	.tx		= rtw89_usb_ops_tx,
	.reset		= rtw89_usb_ops_reset,

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

static inline int rtw_usb_setup(struct rtw89_dev *rtwdev,
				struct usb_interface *intf)
{
	struct usb_device *udev;
	struct rtw_usb *rtwusb;
	int ret = 0;

	rtwdev->dev = &intf->dev;
	udev = usb_get_dev(interface_to_usbdev(intf));

	rtwdev->hci.ops = &rtw89_usb_ops;
	rtwdev->hci.type = RTW89_HCI_TYPE_USB;

	usb_set_intfdata(intf, rtwdev->hw);

	rtwusb = rtw_get_usb_priv(rtwdev);
	rtwusb->udev = udev;

	mutex_init(&rtwusb->usb_buf_mutex);

	mutex_init(&rtwusb->tx_lock);

	pr_info("%s: rtw_usb_parse\n", __func__);
	ret = rtw_usb_parse(rtwdev, intf);
	if (ret) {
		pr_err("rtw_usb_parse failed, ret=%d\n", ret);
		goto err_usb_parse;
	}

	goto finish;

err_usb_parse:
	usb_put_dev(rtwusb->udev);
	usb_set_intfdata(intf, NULL);
	mutex_destroy(&rtwusb->usb_buf_mutex);
	mutex_destroy(&rtwusb->tx_lock);

finish:
	return ret;
}

static int rtw_usb_probe(struct usb_interface *intf,
			 const struct usb_device_id *id)
{
	struct rtw89_dev *rtwdev;
	struct rtw_usb *rtwusb;
	int ret = 0;

	pr_info("%s ===>\n", __func__);

	ret = rtw_os_alloc_hw(&rtwdev, id);
	if (ret) {
		pr_err("rtw_os_core_init fail, ret=%d\n", ret);
		goto finish;
	}

	ret = rtw_usb_setup(rtwdev, intf);
	if (ret) {
		pr_err("rtw_usb_setup fail, ret=%d\n", ret);
		goto err_alloc_hw;
	}

	rtwusb = rtw_get_usb_priv(rtwdev);

	pr_info("%s: usb_interface_configure\n", __func__);
	usb_interface_configure(rtwdev);

	rtwusb->init_done = true;
	SET_IEEE80211_DEV(rtwdev->hw, &intf->dev);

	ret = rtw89_core_register(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to register core\n");
		goto err_usb_setup;
	}

	ret = rtw_usb_init_rx(rtwdev);
	if (ret)
		goto err_core_register;

	ret = rtw_usb_init_tx(rtwdev);
	if (ret)
		goto err_destroy_rxwq;

	goto finish;

//err_destroy_txwq:
	flush_workqueue(rtwusb->txwq);
	destroy_workqueue(rtwusb->txwq);

err_destroy_rxwq:
	flush_workqueue(rtwusb->rxwq);
	destroy_workqueue(rtwusb->rxwq);

err_core_register:
	rtw89_core_unregister(rtwdev);

err_usb_setup:
	usb_put_dev(rtwusb->udev);
	usb_set_intfdata(intf, NULL);
	mutex_destroy(&rtwusb->usb_buf_mutex);
	mutex_destroy(&rtwusb->tx_lock);

err_alloc_hw:
	rtw_os_free_hw(rtwdev);

finish:
	return ret;
}

static void rtw_usb_disconnect(struct usb_interface *intf)
{
	struct ieee80211_hw *hw = usb_get_intfdata(intf);
	struct rtw89_dev *rtwdev;
	struct rtw_usb *rtwusb;

	if (!hw)
		return;

	rtwdev = hw->priv;
	rtwusb = rtw_get_usb_priv(rtwdev);
	rtwusb->init_done = false;

	rtw_tx_queue_purge(rtwusb);
	skb_queue_purge(&rtwusb->rx_queue);
	rtw_kill_handler(&rtwusb->tx_handler);
	rtw_kill_handler(&rtwusb->rx_handler);
	cancel_work_sync(&rtwusb->rx_handler_data->work);
	cancel_work_sync(&rtwusb->tx_handler_data->work);
	destroy_workqueue(rtwusb->rxwq);
	destroy_workqueue(rtwusb->txwq);

	kfree(rtwusb->tx_handler_data);
	kfree(rtwusb->rx_handler_data);

	rtw89_core_unregister(rtwdev);

	if (rtwusb->udev->state != USB_STATE_NOTATTACHED) {
		pr_info("Device still attached, trying to reset\n");
		usb_reset_device(rtwusb->udev);
	}

	usb_put_dev(rtwusb->udev);
	usb_set_intfdata(intf, NULL);
	mutex_destroy(&rtwusb->usb_buf_mutex);
	mutex_destroy(&rtwusb->tx_lock);

	ieee80211_free_hw(hw);
}

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
MODULE_DESCRIPTION("Realtek 802.11ax wireless PCI driver");
MODULE_LICENSE("Dual BSD/GPL");
