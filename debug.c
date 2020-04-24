// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include "core.h"
#include "debug.h"

unsigned int rtw89_debug_mask;
EXPORT_SYMBOL(rtw89_debug_mask);
module_param_named(debug_mask, rtw89_debug_mask, uint, 0644);
MODULE_PARM_DESC(debug_mask, "Debugging mask");

struct rtw89_debugfs_priv {
	struct rtw89_dev *rtwdev;
	int (*cb_read)(struct seq_file *m, void *v);
	ssize_t (*cb_write)(struct file *filp, const char __user *buffer,
			    size_t count, loff_t *loff);
	union {
		u32 cb_data;
	};
};

static int rtw89_debugfs_single_show(struct seq_file *m, void *v)
{
	struct rtw89_debugfs_priv *debugfs_priv = m->private;

	return debugfs_priv->cb_read(m, v);
}

static ssize_t rtw89_debugfs_single_write(struct file *filp,
					  const char __user *buffer,
					  size_t count, loff_t *loff)
{
	struct rtw89_debugfs_priv *debugfs_priv = filp->private_data;

	return debugfs_priv->cb_write(filp, buffer, count, loff);
}

static ssize_t rtw89_debugfs_seq_file_write(struct file *filp,
					    const char __user *buffer,
					    size_t count, loff_t *loff)
{
	struct seq_file *seqpriv = (struct seq_file *)filp->private_data;
	struct rtw89_debugfs_priv *debugfs_priv = seqpriv->private;

	return debugfs_priv->cb_write(filp, buffer, count, loff);
}

static int rtw89_debugfs_single_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, rtw89_debugfs_single_show, inode->i_private);
}

static int rtw89_debugfs_close(struct inode *inode, struct file *filp)
{
	return 0;
}

static const struct file_operations file_ops_single_r = {
	.owner = THIS_MODULE,
	.open = rtw89_debugfs_single_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations file_ops_common_rw = {
	.owner = THIS_MODULE,
	.open = rtw89_debugfs_single_open,
	.release = single_release,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = rtw89_debugfs_seq_file_write,
};

static const struct file_operations file_ops_single_w = {
	.owner = THIS_MODULE,
	.write = rtw89_debugfs_single_write,
	.open = simple_open,
	.release = rtw89_debugfs_close,
};

static ssize_t
rtw89_debug_priv_mac_reg_dump_select(struct file *filp,
				     const char __user *user_buf,
				     size_t count, loff_t *loff)
{
	struct seq_file *m = (struct seq_file *)filp->private_data;
	struct rtw89_debugfs_priv *debugfs_priv = m->private;
	struct rtw89_dev *rtwdev = debugfs_priv->rtwdev;
	char buf[32];
	u32 buf_size;
	ssize_t len;

	buf_size = sizeof(buf);
	if (!count || count >= buf_size)
		return -EINVAL;

	len = simple_write_to_buffer(buf, buf_size - 1, loff, user_buf, count);
	if (len < 0)
		return len;

	buf[*loff - 1] = '\0';

	if (!strcmp(buf, "mac_00")) {
		debugfs_priv->cb_data = RTW89_DBG_SEL_MAC_00;
	} else if (!strcmp(buf, "mac_40")) {
		debugfs_priv->cb_data = RTW89_DBG_SEL_MAC_40;
	} else if (!strcmp(buf, "mac_80")) {
		debugfs_priv->cb_data = RTW89_DBG_SEL_MAC_80;
	} else if (!strcmp(buf, "mac_c0")) {
		debugfs_priv->cb_data = RTW89_DBG_SEL_MAC_C0;
	} else if (!strcmp(buf, "bb")) {
		debugfs_priv->cb_data = RTW89_DBG_SEL_BB;
	} else if (!strcmp(buf, "iqk")) {
		debugfs_priv->cb_data = RTW89_DBG_SEL_IQK;
	} else if (!strcmp(buf, "rfc")) {
		debugfs_priv->cb_data = RTW89_DBG_SEL_RFC;
	} else {
		rtw89_info(rtwdev, "invalid args: [mac_00|mac_40|mac_80|mac_c0|bb|iqk|rfc]\n");
		return -EINVAL;
	}

	rtw89_info(rtwdev, "select mac page dump %d\n", debugfs_priv->cb_data);

	return count;
}

#define RTW89_MAC_PAGE_SIZE		0x100

static int rtw89_debug_priv_mac_reg_dump_get(struct seq_file *m, void *v)
{
	struct rtw89_debugfs_priv *debugfs_priv = m->private;
	struct rtw89_dev *rtwdev = debugfs_priv->rtwdev;
	enum rtw89_debug_mac_reg_sel reg_sel = debugfs_priv->cb_data;
	u32 start, end;
	u32 i, j, k, page;
	u32 val;

	switch (reg_sel) {
	case RTW89_DBG_SEL_MAC_00:
		seq_puts(m, "Debug selected MAC page 0x00\n");
		start = 0x000;
		end = 0x03f;
		break;
	case RTW89_DBG_SEL_MAC_40:
		seq_puts(m, "Debug selected MAC page 0x40\n");
		start = 0x040;
		end = 0x07f;
		break;
	case RTW89_DBG_SEL_MAC_80:
		seq_puts(m, "Debug selected MAC page 0x80\n");
		start = 0x080;
		end = 0x0bf;
		break;
	case RTW89_DBG_SEL_MAC_C0:
		seq_puts(m, "Debug selected MAC page 0xc0\n");
		start = 0x0c0;
		end = 0x0ff;
		break;
	case RTW89_DBG_SEL_BB:
		seq_puts(m, "Debug selected BB register\n");
		start = 0x100;
		end = 0x13f;
		break;
	case RTW89_DBG_SEL_IQK:
		seq_puts(m, "Debug selected IQK register\n");
		start = 0x180;
		end = 0x1bf;
		break;
	case RTW89_DBG_SEL_RFC:
		seq_puts(m, "Debug selected RFC register\n");
		start = 0x1c0;
		end = 0x1ff;
		break;
	default:
		seq_puts(m, "Selected invalid register page\n");
		return -EINVAL;
	}

	for (i = start; i <= end; i++) {
		page = i << 8;
		for (j = page; j < page + RTW89_MAC_PAGE_SIZE; j += 16) {
			seq_printf(m, "%08xh : ", 0x18600000 + j);
			for (k = 0; k < 4; k++) {
				val = rtw89_read32(rtwdev, j + (k << 2));
				seq_printf(m, "%08x ", val);
			}
			seq_puts(m, "\n");
		}
	}

	return 0;
}

static struct rtw89_debugfs_priv rtw89_debug_priv_mac_reg_dump = {
	.cb_read = rtw89_debug_priv_mac_reg_dump_get,
	.cb_write = rtw89_debug_priv_mac_reg_dump_select,
};

#define RTW89_DEBUGFS_MAC_PAGE_SIZE	0x100

static int rtw89_debug_get_mac_page(struct seq_file *m, void *v)
{
	struct rtw89_debugfs_priv *debugfs_priv = m->private;
	struct rtw89_dev *rtwdev = debugfs_priv->rtwdev;
	u32 page = debugfs_priv->cb_data;
	u32 page_max = RTW89_DEBUGFS_MAC_PAGE_SIZE;
	int i, j;

	for (i = 0; i < page_max; ) {
		seq_printf(m, "\n%8.8x  ", i + page);
		for (j = 0; j < 4 && i < page_max; j++, i += 4) {
			seq_printf(m, "%8.8x    ",
				   rtw89_read32(rtwdev, (page | i)));
		}
	}
	seq_puts(m, "\n");
	return 0;
}

#define rtw89_debugfs_impl_mac(page, addr)					\
	static struct rtw89_debugfs_priv rtw89_debug_priv_mac_ ##page = {	\
		.cb_read = rtw89_debug_get_mac_page,				\
		.cb_data = addr,						\
	}

rtw89_debugfs_impl_mac(0, 0x0000);
rtw89_debugfs_impl_mac(10, 0x1000);
rtw89_debugfs_impl_mac(11, 0x1100);
rtw89_debugfs_impl_mac(12, 0x1200);
rtw89_debugfs_impl_mac(13, 0x1300);
rtw89_debugfs_impl_mac(83, 0x8300);
rtw89_debugfs_impl_mac(84, 0x8400);
rtw89_debugfs_impl_mac(88, 0x8800);
rtw89_debugfs_impl_mac(8a, 0x8a00);
rtw89_debugfs_impl_mac(8c, 0x8c00);
rtw89_debugfs_impl_mac(90, 0x9000);
rtw89_debugfs_impl_mac(94, 0x9400);

#define rtw89_debugfs_add(name, mode, fopname, parent)				\
	do {									\
		rtw89_debug_priv_ ##name.rtwdev = rtwdev;			\
		if (!debugfs_create_file(#name, mode,				\
					 parent, &rtw89_debug_priv_ ##name,	\
					 &file_ops_ ##fopname))			\
			pr_debug("Unable to initialize debugfs:%s\n", #name);	\
	} while (0)

#define rtw89_debugfs_add_w(name)						\
	rtw89_debugfs_add(name, S_IFREG | 0222, single_w, debugfs_topdir)
#define rtw89_debugfs_add_rw(name)						\
	rtw89_debugfs_add(name, S_IFREG | 0666, common_rw, debugfs_topdir)
#define rtw89_debugfs_add_r(name)						\
	rtw89_debugfs_add(name, S_IFREG | 0444, single_r, debugfs_topdir)

void rtw89_debugfs_init(struct rtw89_dev *rtwdev)
{
	struct dentry *debugfs_topdir;

	debugfs_topdir = debugfs_create_dir("rtw89",
					    rtwdev->hw->wiphy->debugfsdir);

	rtw89_debugfs_add_r(mac_0);
	rtw89_debugfs_add_r(mac_10);
	rtw89_debugfs_add_r(mac_11);
	rtw89_debugfs_add_r(mac_12);
	rtw89_debugfs_add_r(mac_13);
	rtw89_debugfs_add_r(mac_83);
	rtw89_debugfs_add_r(mac_84);
	rtw89_debugfs_add_r(mac_88);
	rtw89_debugfs_add_r(mac_8a);
	rtw89_debugfs_add_r(mac_8c);
	rtw89_debugfs_add_r(mac_90);
	rtw89_debugfs_add_r(mac_94);
	rtw89_debugfs_add_rw(mac_reg_dump);
}

void __rtw89_debug(struct rtw89_dev *rtwdev,
		   enum rtw89_debug_mask mask,
		   const char *fmt, ...)
{
	struct va_format vaf = {
	.fmt = fmt,
	};

	va_list args;

	va_start(args, fmt);
	vaf.va = &args;

	if (rtw89_debug_mask & mask)
		dev_printk(KERN_DEBUG, rtwdev->dev, "%pV", &vaf);

	va_end(args);
}
EXPORT_SYMBOL(__rtw89_debug);
