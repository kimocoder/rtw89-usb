#ifndef __RTW_USB_H_
#define __RTW_USB_H_

#define RTW_USB_CMD_READ		0xC0
#define RTW_USB_CMD_WRITE		0x40
#define RTW_USB_CMD_REQ			0x05

#define RTW_USB_IS_FULL_SPEED_USB(rtwusb) \
	((rtwusb)->usb_speed == RTW_USB_SPEED_1_1)
#define RTW_USB_IS_HIGH_SPEED(rtwusb)	((rtwusb)->usb_speed == RTW_USB_SPEED_2)
#define RTW_USB_IS_SUPER_SPEED(rtwusb)	((rtwusb)->usb_speed == RTW_USB_SPEED_3)

#define RTW_USB_SUPER_SPEED_BULK_SIZE	1024
#define RTW_USB_HIGH_SPEED_BULK_SIZE	512
#define RTW_USB_FULL_SPEED_BULK_SIZE	64

#define RTW_USB_TX_SEL_HQ		BIT(0)
#define RTW_USB_TX_SEL_LQ		BIT(1)
#define RTW_USB_TX_SEL_NQ		BIT(2)
#define RTW_USB_TX_SEL_EQ		BIT(3)

#define RTW_USB_BULK_IN_EP_IDX		0
#define RTW_USB_IN_INT_EP_IDX		1

#define RTW_USB_MAX_EP_OUT_NUM		8
#define RTW_USB_HW_QUEUE_ENTRY		8
#define RTW_USB_MAX_BULKIN_NUM		2
#define RTW_USB_MAX_BULKOUT_NUM		7

#define RTW_USB_PACKET_OFFSET_SZ	8
#define RTW_USB_MAX_RECVBUF_SZ		32768

#define RTW_USB_RECVBUFF_ALIGN_SZ	8

#define RTW_USB_RXAGG_SIZE		6
#define RTW_USB_RXAGG_TIMEOUT		10

#define RTW_USB_RXCB_NUM		8

#define REG_SYS_CFG2		0x00FC
#define REG_USB_USBSTAT		0xFE11
#define REG_RXDMA_MODE		0x785
#define REG_TXDMA_OFFSET_CHK	0x20C
#define BIT_DROP_DATA_EN	BIT(9)

/* USB Vendor/Product IDs */
#define RTW_USB_VENDOR_ID_REALTEK		0x0bda
#define RTW_USB_PRODUCT_ID_REALTEK_8852A	0x885a

/* helper for USB Ids */

#define RTK_USB_DEVICE(vend, dev, hw_config)	\
	USB_DEVICE(vend, dev),			\
	.driver_info = hw_config,

#define RTK_USB_DEVICE_AND_INTERFACE(vend, dev, cl, sc, pr, hw_config)	\
	USB_DEVICE_AND_INTERFACE_INFO(vend, dev, cl, sc, pr),		\
	.driver_info = hw_config,

/* defined functions */
#define rtw_get_usb_priv(rtwdev) (struct rtw_usb *)((rtwdev)->priv)

enum rtw_usb_burst_size {
	USB_BURST_SIZE_3_0 = 0x0,
	USB_BURST_SIZE_2_0_HS = 0x1,
	USB_BURST_SIZE_2_0_FS = 0x2,
	USB_BURST_SIZE_2_0_OTHERS = 0x3,
	USB_BURST_SIZE_UNDEFINE = 0x7F,
};

enum rtw_usb_speed {
	RTW_USB_SPEED_UNKNOWN	= 0,
	RTW_USB_SPEED_1_1	= 1,
	RTW_USB_SPEED_2		= 2,
	RTW_USB_SPEED_3		= 3,
};

struct rx_usb_ctrl_block {
	u8 *data;
	struct urb *rx_urb;
	struct sk_buff *rx_skb;
	u8 ep_num;
};

struct rtw_usb_work_data {
	struct work_struct work;
	struct rtw89_dev *rtwdev;
};

struct rtw_usb_tx_data {
	u8 sn;
};

struct rtw_usb_tx_cb {
	struct sk_buff *skb;
	struct completion done;
	int status;
};

struct rtw_usb {
	struct rtw89_dev *rtwdev;
	struct usb_device *udev;

	u8 num_in_pipes;
	u8 num_out_pipes;
	u8 in_pipe_type[RTW_USB_MAX_BULKIN_NUM];
	u8 in_pipe[RTW_USB_MAX_BULKIN_NUM];
	u8 out_pipe[RTW_USB_MAX_BULKOUT_NUM];

	u32 bulkout_size;
	u8 usb_speed;
	u8 usb_txagg_num;

	struct completion done;
	struct workqueue_struct *txwq, *rxwq;

	struct sk_buff_head tx_queue[RTW89_DMA_CH_NUM];
	struct sk_buff_head tx_ack_queue;
	struct rtw_usb_work_data *tx_handler_data;

	struct rx_usb_ctrl_block rx_cb[RTW_USB_RXCB_NUM];
	struct sk_buff_head rx_queue;
	struct rtw_usb_work_data *rx_handler_data;
};

static inline struct rtw_usb_tx_data *rtw_usb_get_tx_data(struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	BUILD_BUG_ON(sizeof(struct rtw_usb_tx_data) >
		sizeof(info->status.status_driver_data));

	return (struct rtw_usb_tx_data *)info->status.status_driver_data;
}

#endif
