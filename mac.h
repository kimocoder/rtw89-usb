/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#ifndef __RTW89_MAC_H__
#define __RTW89_MAC_H__

enum rtw89_mac_hwmod_sel {
	RTW89_DMAC_SEL = 0,
	RTW89_CMAC_SEL = 1,

	RTW89_MAC_INVALID,
};

enum rtw89_mac_fwd_target {
	RTW89_FWD_DONT_CARE    = 0,
	RTW89_FWD_TO_HOST      = 1,
	RTW89_FWD_TO_WLAN_CPU  = 2
};

enum rtw89_mac_cpuio_op_cmd_type {
	CPUIO_OP_CMD_GET_1ST_PID = 0,
	CPUIO_OP_CMD_GET_NEXT_PID = 1,
	CPUIO_OP_CMD_ENQ_TO_TAIL = 4,
	CPUIO_OP_CMD_ENQ_TO_HEAD = 5,
	CPUIO_OP_CMD_DEQ = 8,
	CPUIO_OP_CMD_DEQ_ENQ_ALL = 9,
	CPUIO_OP_CMD_DEQ_ENQ_TO_TAIL = 12
};

enum rtw89_mac_wde_dle_port_id {
	WDE_DLE_PORT_ID_DISPATCH = 0,
	WDE_DLE_PORT_ID_PKTIN = 1,
	WDE_DLE_PORT_ID_CMAC0 = 3,
	WDE_DLE_PORT_ID_CMAC1 = 4,
	WDE_DLE_PORT_ID_CPU_IO = 6,
	WDE_DLE_PORT_ID_WDRLS = 7,
	WDE_DLE_PORT_ID_END = 8
};

enum rtw89_mac_wde_dle_queid_wdrls {
	WDE_DLE_QUEID_TXOK = 0,
	WDE_DLE_QUEID_DROP_RETRY_LIMIT = 1,
	WDE_DLE_QUEID_DROP_LIFETIME_TO = 2,
	WDE_DLE_QUEID_DROP_MACID_DROP = 3,
	WDE_DLE_QUEID_NO_REPORT = 4
};

enum rtw89_mac_ple_dle_port_id {
	PLE_DLE_PORT_ID_DISPATCH = 0,
	PLE_DLE_PORT_ID_MPDU = 1,
	PLE_DLE_PORT_ID_SEC = 2,
	PLE_DLE_PORT_ID_CMAC0 = 3,
	PLE_DLE_PORT_ID_CMAC1 = 4,
	PLE_DLE_PORT_ID_WDRLS = 5,
	PLE_DLE_PORT_ID_CPU_IO = 6,
	PLE_DLE_PORT_ID_PLRLS = 7,
	PLE_DLE_PORT_ID_END = 8
};

enum rtw89_mac_ple_dle_queid_plrls {
	PLE_DLE_QUEID_NO_REPORT = 0x0
};

enum rtw89_machdr_frame_type {
	RTW89_MGNT = 0,
	RTW89_CTRL = 1,
	RTW89_DATA = 2,
};

struct rtw89_pwr_cfg {
	u16 addr;
	u8 cut_msk;
	u8 intf_msk;
	u8 base:4;
	u8 cmd:4;
	u8 msk;
	u8 val;
};

#define RTW89_R32_EA		0xEAEAEAEA
#define RTW89_R32_DEAD		0xDEADBEEF

#define PTCL_IDLE_POLL_CNT	10000
#define SW_CVR_DUR_US	8
#define SW_CVR_CNT	8

#define DLE_BOUND_UNIT (8 * 1024)
#define DLE_WAIT_CNT 2000
#define TRXCFG_WAIT_CNT	2000

#define RTW89_WDE_PG_64		64
#define RTW89_WDE_PG_128	128
#define RTW89_WDE_PG_256	256

#define S_AX_WDE_PAGE_SEL_64	0
#define S_AX_WDE_PAGE_SEL_128	1
#define S_AX_WDE_PAGE_SEL_256	2

#define RTW89_PLE_PG_64		64
#define RTW89_PLE_PG_128	128
#define RTW89_PLE_PG_256	256

#define S_AX_PLE_PAGE_SEL_64	0
#define S_AX_PLE_PAGE_SEL_128	1
#define S_AX_PLE_PAGE_SEL_256	2

#define SDIO_LOCAL_BASE_ADDR    0x80000000

#define	PWR_CMD_WRITE		0
#define	PWR_CMD_POLL		1
#define	PWR_CMD_DELAY		2
#define	PWR_CMD_END		3

#define	PWR_INTF_MSK_SDIO	BIT(0)
#define	PWR_INTF_MSK_USB	BIT(1)
#define	PWR_INTF_MSK_PCIE	BIT(2)
#define	PWR_INTF_MSK_ALL	0x7

#define PWR_BASE_MAC		0
#define PWR_BASE_USB		1
#define PWR_BASE_PCIE		2
#define PWR_BASE_SDIO		3

#define	PWR_CUT_MSK_A		BIT(0)
#define	PWR_CUT_MSK_B		BIT(1)
#define	PWR_CUT_MSK_C		BIT(2)
#define	PWR_CUT_MSK_D		BIT(3)
#define	PWR_CUT_MSK_E		BIT(4)
#define	PWR_CUT_MSK_F		BIT(5)
#define	PWR_CUT_MSK_G		BIT(6)
#define	PWR_CUT_MSK_TEST	BIT(7)
#define	PWR_CUT_MSK_ALL		0xFF

#define	PWR_DELAY_US		0
#define	PWR_DELAY_MS		1

struct rtw89_dle_size {
	u16 pge_size;
	u16 lnk_pge_num;
	u16 unlnk_pge_num;
};

struct rtw89_wde_quota {
	u16 hif;
	u16 wcpu;
	u16 pkt_in;
	u16 cpu_io;
};

struct rtw89_ple_quota {
	u16 cma0_tx;
	u16 cma1_tx;
	u16 c2h;
	u16 h2c;
	u16 wcpu;
	u16 mpdu_proc;
	u16 cma0_dma;
	u16 cma1_dma;
	u16 bb_rpt;
	u16 wd_rel;
	u16 cpu_io;
};

struct rtw89_dle_mem {
	enum rtw89_qta_mode mode;
	struct rtw89_dle_size *wde_size;
	struct rtw89_dle_size *ple_size;
	struct rtw89_wde_quota *wde_min_qt;
	struct rtw89_wde_quota *wde_max_qt;
	struct rtw89_ple_quota *ple_min_qt;
	struct rtw89_ple_quota *ple_max_qt;
};

struct rtw89_cpuio_ctrl {
	u16 pkt_num;
	u16 start_pktid;
	u16 end_pktid;
	u8 cmd_type;
	u8 macid;
	u8 src_pid;
	u8 src_qid;
	u8 dst_pid;
	u8 dst_qid;
	u16 pktid;
};

int rtw89_mac_pwr_on(struct rtw89_dev *rtwdev);
void rtw89_mac_pwr_off(struct rtw89_dev *rtwdev);
int rtw89_mac_init(struct rtw89_dev *rtwdev);

#endif
