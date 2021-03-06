/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#ifndef __RTW89_REG_H__
#define __RTW89_REG_H__

#define R_AX_SYS_FUNC_EN 0x0002
#define B_AX_FEN_MREGEN BIT(15)
#define B_AX_FEN_HWPDN BIT(14)
#define B_AX_FEN_ELDR BIT(12)
#define B_AX_FEN_DCORE BIT(11)
#define B_AX_FEN_CPUEN BIT(10)
#define B_AX_FEN_DIOE BIT(9)
#define B_AX_FEN_PCIED BIT(8)
#define B_AX_FEN_PPLL BIT(7)
#define B_AX_FEN_PCIEA BIT(6)
#define B_AX_FEN_USBD BIT(4)
#define B_AX_FEN_UPLL BIT(3)
#define B_AX_FEN_USBA BIT(2)
#define B_AX_FEN_BB_GLB_RSTN BIT(1)
#define B_AX_FEN_BBRSTB BIT(0)

#define R_AX_SYS_CLK_CTRL 0x0008
#define B_AX_CPU_CLK_EN BIT(14)

#define R_AX_SYS_EEPROM_CTRL 0x000A
#define B_AX_AUTOLOAD_SUS BIT(5)

#define R_AX_EFUSE_CTRL 0x0030
#define B_AX_EF_MODE_SEL_SH 30
#define B_AX_EF_MODE_SEL_MSK 0x3
#define B_AX_EF_RDY BIT(29)
#define B_AX_EF_COMP_RESULT BIT(28)
#define B_AX_EF_ADDR_SH 16
#define B_AX_EF_ADDR_MSK 0x7ff
#define B_AX_EF_DATA_SH 0
#define B_AX_EF_DATA_MSK 0xffff

#define R_AX_EFUSE_CTRL_1 0x0038
#define B_AX_EF_PGPD_SH 28
#define B_AX_EF_PGPD_MSK 0x7
#define B_AX_EF_RDT BIT(27)
#define B_AX_EF_VDDQST_SH 24
#define B_AX_EF_VDDQST_MSK 0xf
#define B_AX_EF_PGTS_SH 20
#define B_AX_EF_PGTS_MSK 0xf
#define B_AX_EF_PD_DIS BIT(11)
#define B_AX_EF_POR BIT(10)
#define B_AX_EF_CELL_SEL_SH 8
#define B_AX_EF_CELL_SEL_MSK 0x3

#define R_AX_DBG_CTRL 0x0058
#define B_AX_DBG_SEL1_4BIT GENMASK(31, 30)
#define B_AX_DBG_SEL1_16BIT BIT(27)
#define B_AX_DBG_SEL1 GENMASK(23, 16)
#define B_AX_DBG_SEL0_4BIT GENMASK(15, 14)
#define B_AX_DBG_SEL0_16BIT BIT(11)
#define B_AX_DBG_SEL0 GENMASK(7, 0)

#define R_AX_SYS_SDIO_CTRL 0x0070
#define B_AX_PCIE_AUXCLK_GATE BIT(11)

#define R_AX_PLATFORM_ENABLE 0x0088
#define B_AX_WCPU_EN BIT(1)

#define R_AX_DBG_PORT_SEL 0x00C0
#define B_AX_DEBUG_ST_MSK GENMASK(31, 0)

#define R_AX_SYS_STATUS1 0x00F4
#define B_AX_SEL_0XC0 GENMASK(17, 16)

#define R_AX_WCPU_FW_CTRL 0x01E0
#define B_AX_WCPU_FWDL_STS_MASK GENMASK(7, 5)
#define B_AX_FWDL_PATH_RDY BIT(2)
#define B_AX_H2C_PATH_RDY BIT(1)
#define B_AX_WCPU_FWDL_EN BIT(0)

#define R_AX_BOOT_REASON 0x01E6
#define B_AX_BOOT_REASON_MASK GENMASK(2, 0)

#define R_AX_WLRF_CTRL 0x02F0
#define B_AX_WLRF1_CTRL_7 BIT(15)
#define B_AX_WLRF1_CTRL_6 BIT(14)
#define B_AX_WLRF1_CTRL_5 BIT(13)
#define B_AX_WLRF1_CTRL_4 BIT(12)
#define B_AX_WLRF1_CTRL_3 BIT(11)
#define B_AX_WLRF1_CTRL_2 BIT(10)
#define B_AX_WLRF1_CTRL_1 BIT(9)
#define B_AX_WLRF1_CTRL_0 BIT(8)
#define B_AX_WLRF_CTRL_7 BIT(7)
#define B_AX_WLRF_CTRL_6 BIT(6)
#define B_AX_WLRF_CTRL_5 BIT(5)
#define B_AX_WLRF_CTRL_4 BIT(4)
#define B_AX_WLRF_CTRL_3 BIT(3)
#define B_AX_WLRF_CTRL_2 BIT(2)
#define B_AX_WLRF_CTRL_1 BIT(1)
#define B_AX_WLRF_CTRL_0 BIT(0)

#define R_AX_USB_BT_BRIDGE 0x11A8
#define B_AX_R_DIS_BTBRI_SS_SYSON BIT(2)
#define B_AX_R_DIS_BTBRI_SS_STS BIT(1)
#define B_AX_R_DIS_BTBRI_L1U2_SYS BIT(0)

#define R_AX_PCIE_DBG_CTRL 0x11C0
#define B_AX_DBG_SEL GENMASK(23, 16)
#define B_AX_LOOPBACK_DBG_SEL GENMASK(15, 13)
#define B_AX_PCIE_DBG_SEL BIT(12)
#define B_AX_MRD_TIMEOUT_EN BIT(10)
#define B_AX_ASFF_FULL_NO_STK BIT(1)
#define B_AX_EN_STUCK_DBG BIT(0)

#define R_AX_USB_STATUS 0x11F0
#define B_AX_USB_EP_NUM_SH 4
#define B_AX_USB_EP_NUM_MSK 0xF
#define B_AX_R_SSIC_EN BIT(2)
#define B_AX_R_USB2_SEL BIT(1)
#define B_AX_MODE_HS BIT(0)

#define R_AX_PHYREG_SET 0x8040
#define B_AX_PHYREG_SET_SH 0
#define B_AX_PHYREG_SET_MSK 0xf
#define B_AX_PHYREG_SET_ALL_CYCLE BIT(3)

#define R_AX_HCI_FUNC_EN 0x8380
#define B_AX_HCI_RXDMA_EN BIT(1)
#define B_AX_HCI_TXDMA_EN BIT(0)

#define R_AX_DMAC_FUNC_EN 0x8400
#define B_AX_MAC_FUNC_EN BIT(30)
#define B_AX_DMAC_FUNC_EN BIT(29)
#define B_AX_MPDU_PROC_EN BIT(28)
#define B_AX_WD_RLS_EN BIT(27)
#define B_AX_DLE_WDE_EN BIT(26)
#define B_AX_TXPKT_CTRL_EN BIT(25)
#define B_AX_STA_SCH_EN BIT(24)
#define B_AX_DLE_PLE_EN BIT(23)
#define B_AX_PKT_BUF_EN BIT(22)
#define B_AX_DMAC_TBL_EN BIT(21)
#define B_AX_PKT_IN_EN BIT(20)
#define B_AX_DLE_CPUIO_EN BIT(19)
#define B_AX_DISPATCHER_EN BIT(18)
#define B_AX_MAC_SEC_EN BIT(16)

#define R_AX_DMAC_CLK_EN 0x8404
#define B_AX_WD_RLS_CLK_EN BIT(27)
#define B_AX_DLE_WDE_CLK_EN BIT(26)
#define B_AX_TXPKT_CTRL_CLK_EN BIT(25)
#define B_AX_STA_SCH_CLK_EN BIT(24)
#define B_AX_DLE_PLE_CLK_EN BIT(23)
#define B_AX_PKT_IN_CLK_EN BIT(20)
#define B_AX_DLE_CPUIO_CLK_EN BIT(19)
#define B_AX_DISPATCHER_CLK_EN BIT(18)
#define B_AX_MAC_SEC_CLK_EN BIT(16)

#define R_AX_DMAC_ERR_ISR 0x8524

#define R_AX_DISPATCHER_GLOBAL_SETTING_0 0x8800
#define B_AX_PL_PAGE_128B_SEL BIT(9)
#define B_AX_WD_PAGE_64B_SEL BIT(8)
#define R_AX_OTHER_DISPATCHER_ERR_ISR 0x8804
#define R_AX_HOST_DISPATCHER_ERR_ISR 0x8808
#define R_AX_CPU_DISPATCHER_ERR_ISR 0x880C
#define R_AX_TX_ADDRESS_INFO_MODE_SETTING 0x8810
#define B_AX_HOST_ADDR_INFO_8B_SEL BIT(0)

#define R_AX_HOST_DISPATCHER_ERR_IMR 0x8850
#define B_AX_HDT_OFFSET_UNMATCH_INT_EN BIT(7)
#define B_AX_HDT_PKT_FAIL_DBG_INT_EN BIT(2)

#define R_AX_CPU_DISPATCHER_ERR_IMR 0x8854
#define B_AX_CPU_SHIFT_EN_ERR_INT_EN BIT(25)

#define R_AX_RXDMA_SETTING 0x8908
#define B_AX_PLE_BURST_READ BIT(24)
#define B_AX_REQ_DEPTH_MASK GENMASK(17,16)
#define B_AX_BULK_TH_OPT BIT(10)
#define B_AX_BURST_CNT_MASK GENMASK(9, 8)
#define B_AX_BULK_SIZE GENMASK(1, 0)

#define R_AX_HCI_FC_CTRL 0x8A00
#define B_AX_HCI_FC_CH12_FULL_COND_MASK GENMASK(11, 10)
#define B_AX_HCI_FC_WP_CH811_FULL_COND_MASK GENMASK(9, 8)
#define B_AX_HCI_FC_WP_CH07_FULL_COND_MASK GENMASK(7, 6)
#define B_AX_HCI_FC_WD_FULL_COND_MASK GENMASK(5, 4)
#define B_AX_HCI_FC_CH12_EN BIT(3)
#define B_AX_HCI_FC_MODE_MASK GENMASK(2, 1)
#define B_AX_HCI_FC_EN BIT(0)

#define R_AX_CH_PAGE_CTRL 0x8A04
#define B_AX_PREC_PAGE_CH12_MASK GENMASK(23, 16)
#define B_AX_PREC_PAGE_CH011_MASK GENMASK(7, 0)

#define B_AX_MAX_PG_MASK GENMASK(27, 16)
#define B_AX_MIN_PG_MASK GENMASK(11, 0)
#define B_AX_GRP BIT(31)
#define R_AX_ACH0_PAGE_CTRL 0x8A10
#define R_AX_ACH1_PAGE_CTRL 0x8A14
#define R_AX_ACH2_PAGE_CTRL 0x8A18
#define R_AX_ACH3_PAGE_CTRL 0x8A1C
#define R_AX_ACH4_PAGE_CTRL 0x8A20
#define R_AX_ACH5_PAGE_CTRL 0x8A24
#define R_AX_ACH6_PAGE_CTRL 0x8A28
#define R_AX_ACH7_PAGE_CTRL 0x8A2C
#define R_AX_CH8_PAGE_CTRL 0x8A30
#define R_AX_CH9_PAGE_CTRL 0x8A34
#define R_AX_CH10_PAGE_CTRL 0x8A38
#define R_AX_CH11_PAGE_CTRL 0x8A3C

#define B_AX_AVAL_PG_MASK GENMASK(27, 16)
#define B_AX_USE_PG_MASK GENMASK(11, 0)
#define R_AX_ACH0_PAGE_INFO 0x8A50
#define R_AX_ACH1_PAGE_INFO 0x8A54
#define R_AX_ACH2_PAGE_INFO 0x8A58
#define R_AX_ACH3_PAGE_INFO 0x8A5C
#define R_AX_ACH4_PAGE_INFO 0x8A60
#define R_AX_ACH5_PAGE_INFO 0x8A64
#define R_AX_ACH6_PAGE_INFO 0x8A68
#define R_AX_ACH7_PAGE_INFO 0x8A6C
#define R_AX_CH8_PAGE_INFO 0x8A70
#define R_AX_CH9_PAGE_INFO 0x8A74
#define R_AX_CH10_PAGE_INFO 0x8A78
#define R_AX_CH11_PAGE_INFO 0x8A7C
#define R_AX_CH12_PAGE_INFO 0x8A80

#define R_AX_PUB_PAGE_INFO3 0x8A8C
#define B_AX_G1_AVAL_PG_MASK GENMASK(28, 16)
#define B_AX_G0_AVAL_PG_MASK GENMASK(12, 0)

#define R_AX_PUB_PAGE_CTRL1 0x8A90
#define B_AX_PUBPG_G1_MASK GENMASK(28, 16)
#define B_AX_PUBPG_G0_MASK GENMASK(12, 0)

#define R_AX_PUB_PAGE_CTRL2 0x8A94
#define B_AX_PUBPG_ALL_MASK GENMASK(12, 0)

#define R_AX_PUB_PAGE_INFO1 0x8A98
#define B_AX_G1_USE_PG_MASK GENMASK(28, 16)
#define B_AX_G0_USE_PG_MASK GENMASK(12, 0)

#define R_AX_PUB_PAGE_INFO2 0x8A9C
#define B_AX_PUB_AVAL_PG_MASK GENMASK(12, 0)

#define R_AX_WP_PAGE_CTRL1 0x8AA0
#define B_AX_PREC_PAGE_WP_CH811_MASK GENMASK(24, 16)
#define B_AX_PREC_PAGE_WP_CH07_MASK GENMASK(8, 0)

#define R_AX_WP_PAGE_CTRL2 0x8AA4
#define B_AX_WP_THRD_MASK GENMASK(12, 0)

#define R_AX_WP_PAGE_INFO1 0x8AA8
#define B_AX_WP_AVAL_PG_MASK GENMASK(28, 16)

#define R_AX_WDE_PKTBUF_CFG 0x8C08
#define B_AX_WDE_START_BOUND_MASK GENMASK(13, 8)
#define B_AX_WDE_PAGE_SEL_MASK 0x3
#define B_AX_WDE_FREE_PAGE_NUM_MASK GENMASK(28, 16)
#define R_AX_WDE_ERR_ISR 0x8C3C

#define B_AX_WDE_MAX_SIZE_MASK GENMASK(27, 16)
#define B_AX_WDE_MIN_SIZE_MASK GENMASK(11, 0)
#define R_AX_WDE_QTA0_CFG 0x8C40
#define R_AX_WDE_QTA1_CFG 0x8C44
#define R_AX_WDE_QTA2_CFG 0x8C48
#define R_AX_WDE_QTA3_CFG 0x8C4C
#define R_AX_WDE_QTA4_CFG 0x8C50

#define B_AX_DLE_PUB_PGNUM GENMASK(12, 0)
#define B_AX_DLE_FREE_HEADPG GENMASK(11, 0)
#define B_AX_DLE_FREE_TAILPG GENMASK(27, 16)
#define B_AX_DLE_USE_PGNUM GENMASK(27, 16)
#define B_AX_DLE_RSV_PGNUM GENMASK(11, 0)

#define R_AX_WDE_INI_STATUS 0x8D00
#define B_AX_WDE_Q_MGN_INI_RDY BIT(1)
#define B_AX_WDE_BUF_MGN_INI_RDY BIT(0)
#define WDE_MGN_INI_RDY (B_AX_WDE_Q_MGN_INI_RDY | B_AX_WDE_BUF_MGN_INI_RDY)
#define R_AX_WDE_DBG_FUN_INTF_CTL 0x8D10
#define B_AX_WDE_DFI_ACTIVE BIT(31)
#define B_AX_WDE_DFI_TRGSEL GENMASK(19, 16)
#define B_AX_WDE_DFI_ADDR GENMASK(15, 0)
#define R_AX_WDE_DBG_FUN_INTF_DATA 0x8D14
#define B_AX_WDE_DFI_DATA_MSK GENMASK(31, 0)

#define R_AX_PLE_PKTBUF_CFG 0x9008
#define B_AX_PLE_START_BOUND_MASK GENMASK(13, 8)
#define B_AX_PLE_PAGE_SEL_MASK 0x3
#define B_AX_PLE_FREE_PAGE_NUM_MASK GENMASK(28, 16)

#define R_AX_PLE_ERR_IMR 0x9038
#define B_AX_PLE_GETNPG_STRPG_ERR_INT_EN BIT(5)

#define R_AX_PLE_ERR_FLAG_ISR 0x903C
#define B_AX_PLE_MAX_SIZE_MASK GENMASK(27, 16)
#define B_AX_PLE_MIN_SIZE_MASK GENMASK(11, 0)
#define R_AX_PLE_QTA0_CFG 0x9040
#define R_AX_PLE_QTA1_CFG 0x9044
#define R_AX_PLE_QTA2_CFG 0x9048
#define R_AX_PLE_QTA3_CFG 0x904C
#define R_AX_PLE_QTA4_CFG 0x9050
#define R_AX_PLE_QTA5_CFG 0x9054
#define R_AX_PLE_QTA6_CFG 0x9058
#define R_AX_PLE_QTA7_CFG 0x905C
#define R_AX_PLE_QTA8_CFG 0x9060
#define R_AX_PLE_QTA9_CFG 0x9064
#define R_AX_PLE_QTA10_CFG 0x9068

#define R_AX_PLE_INI_STATUS 0x9100
#define B_AX_PLE_Q_MGN_INI_RDY BIT(1)
#define B_AX_PLE_BUF_MGN_INI_RDY BIT(0)
#define PLE_MGN_INI_RDY (B_AX_PLE_Q_MGN_INI_RDY | B_AX_PLE_BUF_MGN_INI_RDY)
#define R_AX_PLE_DBG_FUN_INTF_CTL 0x9110
#define B_AX_PLE_DFI_ACTIVE BIT(31)
#define B_AX_PLE_DFI_TRGSEL GENMASK(19, 16)
#define B_AX_PLE_DFI_ADDR GENMASK(15, 0)
#define R_AX_PLE_DBG_FUN_INTF_DATA 0x9114
#define B_AX_PLE_DFI_DATA_MSK GENMASK(31, 0)

#define R_AX_RLSRPT0_CFG1 0x9414
#define B_AX_RLSRPT0_TO_MASK GENMASK(23, 16)
#define B_AX_RLSRPT0_AGGNUM_MASK GENMASK(7, 0)
#define R_AX_WDRLS_ERR_ISR 0x9434

#define R_AX_BBRPT_COM_ERR_IMR_ISR 0x960C
#define R_AX_BBRPT_CHINFO_ERR_IMR_ISR 0x962C
#define R_AX_BBRPT_DFS_ERR_IMR_ISR 0x963C
#define R_AX_LA_ERRFLAG 0x966C

#define R_AX_WD_BUF_REQ 0x9800
#define R_AX_PL_BUF_REQ 0x9820
#define B_AX_BUF_REQ_EXEC BIT(31)
#define B_AX_BUF_REQ_QUOTA_ID_MASK GENMASK(23, 16)
#define B_AX_BUF_REQ_LEN_MASK GENMASK(15, 0)

#define R_AX_WD_BUF_STATUS 0x9804
#define R_AX_PL_BUF_STATUS 0x9804
#define B_AX_BUF_STAT_DONE BIT(31)
#define B_AX_BUF_STAT_PKTID_MASK GENMASK(11, 0)

#define R_AX_WD_CPUQ_OP_0 0x9810
#define R_AX_PL_CPUQ_OP_0 0x9830
#define B_AX_CPUQ_OP_EXEC BIT(31)
#define B_AX_CPUQ_OP_CMD_TYPE_MASK GENMASK(27, 24)
#define B_AX_CPUQ_OP_MACID_MASK GENMASK(23, 16)
#define B_AX_CPUQ_OP_PKTNUM_MASK GENMASK(7, 0)

#define R_AX_WD_CPUQ_OP_1 0x9814
#define R_AX_PL_CPUQ_OP_1 0x9834
#define B_AX_CPUQ_OP_SRC_PID_MASK GENMASK(24, 22)
#define B_AX_CPUQ_OP_SRC_QID_MASK GENMASK(21, 16)
#define B_AX_CPUQ_OP_DST_PID_MASK GENMASK(8, 6)
#define B_AX_CPUQ_OP_DST_QID_MASK GENMASK(5, 0)

#define R_AX_WD_CPUQ_OP_2 0x9818
#define R_AX_PL_CPUQ_OP_2 0x9838
#define B_AX_CPUQ_OP_STRT_PKTID_MASK GENMASK(27, 15)
#define B_AX_CPUQ_OP_END_PKTID_MASK GENMASK(11, 0)

#define R_AX_WD_CPUQ_OP_STATUS 0x981C
#define R_AX_PL_CPUQ_OP_STATUS 0x983C
#define B_AX_CPUQ_OP_STAT_DONE BIT(31)
#define B_AX_CPUQ_OP_PKTID_MASK GENMASK(11, 0)
#define R_AX_CPUIO_ERR_ISR 0x9844

#define R_AX_SEC_ERR_IMR_ISR 0x991C

#define R_AX_PKTIN_SETTING 0x9A00
#define B_AX_WD_ADDR_INFO_LENGTH BIT(1)
#define R_AX_PKTIN_ERR_ISR 0x9A24

#define R_AX_MPDU_TX_ERR_ISR 0x9BF0

#define R_AX_MPDU_PROC 0x9C00
#define B_AX_A_ICV_ERR BIT(1)
#define B_AX_APPEND_FCS BIT(0)

#define R_AX_ACTION_FWD0 0x9C04
#define TRXCFG_MPDU_PROC_ACT_FRWD 0x02A95A95

#define R_AX_TF_FWD 0x9C14
#define TRXCFG_MPDU_PROC_TF_FRWD 0x0000AA55

#define R_AX_CUT_AMSDU_CTRL 0x9C40
#define TRXCFG_MPDU_PROC_CUT_CTRL	0x010E05F0

#define R_AX_MPDU_RX_ERR_ISR 0x9CF0

#define R_AX_SEC_ENG_CTRL 0x9D00
#define B_AX_CLK_EN_CGCMP BIT(10)
#define B_AX_CLK_EN_WAPI BIT(9)
#define B_AX_CLK_EN_WEP_TKIP BIT(8)
#define B_AX_BMC_MGNT_DEC BIT(5)
#define B_AX_UC_MGNT_DEC BIT(4)
#define B_AX_MC_DEC BIT(3)
#define B_AX_BC_DEC BIT(2)
#define B_AX_SEC_RX_DEC BIT(1)
#define B_AX_SEC_TX_ENC BIT(0)

#define R_AX_SEC_MPDU_PROC 0x9D04
#define B_AX_APPEND_ICV BIT(1)
#define B_AX_APPEND_MIC BIT(0)

#define R_AX_SS_CTRL 0x9E10
#define B_AX_SS_INIT_DONE_1 BIT(31)
#define B_AX_SS_WARM_INIT_FLG BIT(29)
#define B_AX_SS_EN BIT(0)

#define R_AX_SS_MACID_PAUSE_0 0x9EB0
#define B_AX_SS_MACID31_0_PAUSE_SH 0
#define B_AX_SS_MACID31_0_PAUSE_MSK 0xffffffffL

#define R_AX_SS_MACID_PAUSE_1 0x9EB4
#define B_AX_SS_MACID63_32_PAUSE_SH 0
#define B_AX_SS_MACID63_32_PAUSE_MSK 0xffffffffL

#define R_AX_SS_MACID_PAUSE_2 0x9EB8
#define B_AX_SS_MACID95_64_PAUSE_SH 0
#define B_AX_SS_MACID95_64_PAUSE_MSK 0xffffffffL

#define R_AX_SS_MACID_PAUSE_3 0x9EBC
#define B_AX_SS_MACID127_96_PAUSE_SH 0
#define B_AX_SS_MACID127_96_PAUSE_MSK 0xffffffffL

#define R_AX_STA_SCHEDULER_ERR_ISR 0x9EF4

#define R_AX_TXPKTCTL_ERR_IMR_ISR 0x9F1C
#define R_AX_TXPKTCTL_ERR_IMR_ISR_B1 0x9F2C
#define B_AX_TXPKTCTL_USRCTL_RLSBMPLEN_ERR_INT_EN BIT(3)
#define B_AX_TXPKTCTL_USRCTL_RDNRLSCMD_ERR_INT_EN BIT(2)

#define R_AX_DBG_FUN_INTF_CTL 0x9F30
#define B_AX_DFI_ACTIVE BIT(31)
#define B_AX_DFI_TRGSEL GENMASK(19, 16)
#define B_AX_DFI_ADDR GENMASK(15, 0)
#define R_AX_DBG_FUN_INTF_DATA 0x9F34
#define B_AX_DFI_DATA_MSK GENMASK(31, 0)

#define R_AX_AFE_CTRL1 0x0024

#define B_AX_R_SYM_WLCMAC1_P4_PC_EN BIT(4)
#define B_AX_R_SYM_WLCMAC1_P3_PC_EN BIT(3)
#define B_AX_R_SYM_WLCMAC1_P2_PC_EN BIT(2)
#define B_AX_R_SYM_WLCMAC1_P1_PC_EN BIT(1)
#define B_AX_R_SYM_WLCMAC1_PC_EN BIT(0)

#define R_AX_SYS_ISO_CTRL_EXTEND 0x0080
#define B_AX_CMAC1_FEN BIT(30)
#define B_AX_R_SYM_FEN_WLPHYGLB_1 BIT(17)
#define B_AX_R_SYM_FEN_WLPHYFUN_1 BIT(16)
#define B_AX_R_SYM_ISO_CMAC12PP BIT(5)

#define R_AX_CMAC_FUNC_EN 0xC000
#define R_AX_CMAC_FUNC_EN_C1 0xE000
#define B_AX_CMAC_CRPRT BIT(31)
#define B_AX_CMAC_EN BIT(30)
#define B_AX_CMAC_TXEN BIT(29)
#define B_AX_CMAC_RXEN BIT(28)
#define B_AX_FORCE_CMACREG_GCKEN BIT(15)
#define B_AX_PHYINTF_EN BIT(5)
#define B_AX_CMAC_DMA_EN BIT(4)
#define B_AX_PTCLTOP_EN BIT(3)
#define B_AX_SCHEDULER_EN BIT(2)
#define B_AX_TMAC_EN BIT(1)
#define B_AX_RMAC_EN BIT(0)

#define R_AX_CK_EN 0xC004
#define R_AX_CK_EN_C1 0xE004
#define B_AX_CMAC_CKEN BIT(30)
#define B_AX_PHYINTF_CKEN BIT(5)
#define B_AX_CMAC_DMA_CKEN BIT(4)
#define B_AX_PTCLTOP_CKEN BIT(3)
#define B_AX_SCHEDULER_CKEN BIT(2)
#define B_AX_TMAC_CKEN BIT(1)
#define B_AX_RMAC_CKEN BIT(0)

#define R_AX_TX_SUB_CARRIER_VALUE 0xC088
#define R_AX_TX_SUB_CARRIER_VALUE_C1 0xE088
#define B_AX_TXSC_80M_MASK GENMASK(11, 8)
#define B_AX_TXSC_40M_MASK GENMASK(7, 4)
#define B_AX_TXSC_20M_MASK GENMASK(3, 0)

#define R_AX_CMAC_ERR_ISR 0xC164
#define R_AX_CMAC_ERR_ISR_C1 0xE164

#define R_AX_MACID_SLEEP_0 0xC2C0
#define R_AX_MACID_SLEEP_0_C1 0xE2C0
#define B_AX_MACID31_0_SLEEP_SH 0
#define B_AX_MACID31_0_SLEEP_MSK 0xffffffffL

#define R_AX_MACID_SLEEP_1 0xC2C4
#define R_AX_MACID_SLEEP_1_C1 0xE2C4
#define B_AX_MACID63_32_SLEEP_SH 0
#define B_AX_MACID63_32_SLEEP_MSK 0xffffffffL

#define R_AX_MACID_SLEEP_2 0xC2C8
#define R_AX_MACID_SLEEP_2_C1 0xE2C8
#define B_AX_MACID95_64_SLEEP_SH 0
#define B_AX_MACID95_64_SLEEP_MSK 0xffffffffL

#define R_AX_MACID_SLEEP_3 0xC2CC
#define R_AX_MACID_SLEEP_3_C1 0xE2CC
#define B_AX_MACID127_96_SLEEP_SH 0
#define B_AX_MACID127_96_SLEEP_MSK 0xffffffffL

#define R_AX_CCA_CFG_0 0xC340
#define R_AX_CCA_CFG_0_C1 0xE340
#define B_AX_BTCCA_EN BIT(5)
#define B_AX_EDCCA_EN BIT(4)
#define B_AX_SEC80_EN BIT(3)
#define B_AX_SEC40_EN BIT(2)
#define B_AX_SEC20_EN BIT(1)
#define B_AX_CCA_EN BIT(0)

#define R_AX_CTN_TXEN 0xC348
#define R_AX_CTN_TXEN_C1 0xE348
#define B_AX_CTN_TXEN_TWT_1 BIT(15)
#define B_AX_CTN_TXEN_TWT_0 BIT(14)
#define B_AX_CTN_TXEN_ULQ BIT(13)
#define B_AX_CTN_TXEN_BCNQ BIT(12)
#define B_AX_CTN_TXEN_HGQ BIT(11)
#define B_AX_CTN_TXEN_CPUMGQ BIT(10)
#define B_AX_CTN_TXEN_MGQ1 BIT(9)
#define B_AX_CTN_TXEN_MGQ BIT(8)
#define B_AX_CTN_TXEN_VO_1 BIT(7)
#define B_AX_CTN_TXEN_VI_1 BIT(6)
#define B_AX_CTN_TXEN_BK_1 BIT(5)
#define B_AX_CTN_TXEN_BE_1 BIT(4)
#define B_AX_CTN_TXEN_VO_0 BIT(3)
#define B_AX_CTN_TXEN_VI_0 BIT(2)
#define B_AX_CTN_TXEN_BK_0 BIT(1)
#define B_AX_CTN_TXEN_BE_0 BIT(0)

#define R_AX_CCA_CONTROL 0xC390
#define R_AX_CCA_CONTROL_C1 0xE390
#define B_AX_TB_CHK_TX_NAV BIT(31)
#define B_AX_TB_CHK_BASIC_NAV BIT(30)
#define B_AX_TB_CHK_BTCCA BIT(29)
#define B_AX_TB_CHK_EDCCA BIT(28)
#define B_AX_TB_CHK_CCA_S80 BIT(27)
#define B_AX_TB_CHK_CCA_S40 BIT(26)
#define B_AX_TB_CHK_CCA_S20 BIT(25)
#define B_AX_TB_CHK_CCA_P20 BIT(24)
#define B_AX_SIFS_CHK_BTCCA BIT(21)
#define B_AX_SIFS_CHK_EDCCA BIT(20)
#define B_AX_SIFS_CHK_CCA_S80 BIT(19)
#define B_AX_SIFS_CHK_CCA_S40 BIT(18)
#define B_AX_SIFS_CHK_CCA_S20 BIT(17)
#define B_AX_SIFS_CHK_CCA_P20 BIT(16)
#define B_AX_CTN_CHK_TXNAV BIT(8)
#define B_AX_CTN_CHK_INTRA_NAV BIT(7)
#define B_AX_CTN_CHK_BASIC_NAV BIT(6)
#define B_AX_CTN_CHK_BTCCA BIT(5)
#define B_AX_CTN_CHK_EDCCA BIT(4)
#define B_AX_CTN_CHK_CCA_S80 BIT(3)
#define B_AX_CTN_CHK_CCA_S40 BIT(2)
#define B_AX_CTN_CHK_CCA_S20 BIT(1)
#define B_AX_CTN_CHK_CCA_P20 BIT(0)

#define R_AX_SCHEDULE_ERR_IMR 0xC3E8
#define R_AX_SCHEDULE_ERR_IMR_C1 0xE3E8
#define B_AX_SORT_NON_IDLE_ERR_INT_EN BIT(1)
#define B_AX_FSM_TIMEOUT_ERR_INT_EN BIT(0)

#define R_AX_SCHEDULE_ERR_ISR 0xC3EC
#define R_AX_SCHEDULE_ERR_ISR_C1 0xE3EC

#define R_AX_SCH_DBG_SEL 0xC3F4
#define R_AX_SCH_DBG_SEL_C1 0xE3F4
#define B_AX_SCH_DBG_EN BIT(16)
#define B_AX_SCH_CFG_CMD_SEL GENMASK(15, 8)
#define B_AX_SCH_DBG_SEL_MSK GENMASK(7, 0)

#define R_AX_SCH_DBG 0xC3F8
#define R_AX_SCH_DBG_C1 0xE3F8
#define B_AX_SCHEDULER_DBG_MSK GENMASK(31, 0)

#define R_AX_PTCL_IMR0 0xC6C0
#define R_AX_PTCL_IMR0_C1 0xE6C0
#define B_AX_F2PCMD_USER_ALLC_ERR_INT_EN BIT(28)
#define B_AX_TX_RECORD_PKTID_ERR_INT_EN BIT(23)

#define R_AX_PTCL_ISR0 0xC6C4
#define R_AX_PTCL_ISR0_C1 0xE6C4

#define R_AX_PTCL_TX_CTN_SEL 0xC6EC
#define R_AX_PTCL_TX_CTN_SEL_C1 0xE6EC
#define B_AX_PTCL_TX_ON_STAT BIT(7)

#define R_AX_PTCL_DBG_INFO 0xC6F0
#define R_AX_PTCL_DBG_INFO_C1 0xE6F0
#define B_AX_PTCL_DBG_INFO_MSK GENMASK(31, 0)
#define R_AX_PTCL_DBG 0xC6F4
#define R_AX_PTCL_DBG_C1 0xE6F4
#define B_AX_PTCL_DBG_EN BIT(8)
#define B_AX_PTCL_DBG_SEL GENMASK(7, 0)

#define R_AX_DLE_CTRL 0xC800
#define R_AX_DLE_CTRL_C1 0xE800
#define B_AX_NO_RESERVE_PAGE_ERR_IMR BIT(23)

#define R_AX_TCR1 0xCA04
#define R_AX_TCR1_C1 0xEA04
#define B_AX_TXDFIFO_THRESHOLD GENMASK(31, 28)
#define B_AX_TCR_CCK_LOCK_CLK BIT(27)
#define B_AX_TCR_FORCE_READ_TXDFIFO BIT(26)
#define B_AX_TCR_USTIME GENMASK(23, 16)
#define B_AX_TCR_SMOOTH_VAL BIT(15)
#define B_AX_TCR_SMOOTH_CTRL BIT(14)
#define B_AX_CS_REQ_VAL BIT(13)
#define B_AX_CS_REQ_SEL BIT(12)
#define B_AX_TCR_ZLD_USTIME_AFTERPHYTXON GENMASK(11, 8)
#define B_AX_TCR_TXTIMEOUT GENMASK(7, 0)

#define R_AX_MACTX_DBG_SEL_CNT 0xCA20
#define R_AX_MACTX_DBG_SEL_CNT_C1 0xEA20
#define B_AX_MACTX_MPDU_CNT GENMASK(31, 24)
#define B_AX_MACTX_DMA_CNT GENMASK(23, 16)
#define B_AX_LENGTH_ERR_FLAG_U3 BIT(11)
#define B_AX_LENGTH_ERR_FLAG_U2 BIT(10)
#define B_AX_LENGTH_ERR_FLAG_U1 BIT(9)
#define B_AX_LENGTH_ERR_FLAG_U0 BIT(8)
#define B_AX_DBGSEL_MACTX GENMASK(5, 0)

#define R_AX_WMAC_TX_CTRL_DEBUG 0xCAE4
#define R_AX_WMAC_TX_CTRL_DEBUG_C1 0xEAE4
#define B_AX_TX_CTRL_DEBUG_SEL GENMASK(3, 0)

#define R_AX_WMAC_TX_INFO0_DEBUG 0xCAE8
#define R_AX_WMAC_TX_INFO0_DEBUG_C1 0xEAE8
#define B_AX_TX_CTRL_INFO_P0_MSK GENMASK(31, 0)

#define R_AX_WMAC_TX_INFO1_DEBUG 0xCAEC
#define R_AX_WMAC_TX_INFO1_DEBUG_C1 0xEAEC
#define B_AX_TX_CTRL_INFO_P1_MSK GENMASK(31, 0)

#define R_AX_RSP_CHK_SIG 0xCC00
#define R_AX_RSP_CHK_SIG_C1 0xEC00
#define B_AX_RSP_CHK_TX_NAV BIT(27)
#define B_AX_RSP_CHK_INTRA_NAV BIT(26)
#define B_AX_RSP_CHK_BASIC_NAV BIT(25)
#define B_AX_RSP_CHK_SEC_CCA_80 BIT(24)
#define B_AX_RSP_CHK_SEC_CCA_40 BIT(23)
#define B_AX_RSP_CHK_SEC_CCA_20 BIT(22)
#define B_AX_RSP_CHK_BTCCA BIT(21)
#define B_AX_RSP_CHK_EDCCA BIT(20)
#define B_AX_RSP_CHK_CCA BIT(19)

#define R_AX_MAC_LOOPBACK 0xCC20
#define R_AX_MAC_LOOPBACK_C1 0xEC20
#define B_AX_MACLBK_EN BIT(0)

#define R_AX_WMAC_TX_TF_INFO_0 0xCCD0
#define R_AX_WMAC_TX_TF_INFO_0_C1 0xECD0
#define B_AX_WMAC_TX_TF_INFO_SEL GENMASK(2, 0)

#define R_AX_WMAC_TX_TF_INFO_1 0xCCD4
#define R_AX_WMAC_TX_TF_INFO_1_C1 0xECD4
#define B_AX_WMAC_TX_TF_INFO_P0 GENMASK(31, 0)

#define R_AX_WMAC_TX_TF_INFO_2 0xCCD8
#define R_AX_WMAC_TX_TF_INFO_2_C1 0xECD8
#define B_AX_WMAC_TX_TF_INFO_P1 GENMASK(31, 0)

#define R_AX_TMAC_ERR_IMR_ISR 0xCCEC
#define R_AX_TMAC_ERR_IMR_ISR_C1 0xECEC

#define R_AX_DBGSEL_TRXPTCL 0xCCF4
#define R_AX_DBGSEL_TRXPTCL_C1 0xECF4
#define B_AX_DBGSEL_TRXPTCL_MSK GENMASK(5, 0)

#define R_AX_PHYINFO_ERR_IMR 0xCCFE
#define R_AX_PHYINFO_ERR_IMR_C1 0xECFE
#define B_AX_CSI_ON_TIMEOUT_INT_EN BIT(5)
#define B_AX_STS_ON_TIMEOUT_INT_EN BIT(4)
#define B_AX_DATA_ON_TIMEOUT_INT_EN BIT(3)
#define B_AX_OFDM_CCA_TIMEOUT_INT_EN BIT(2)
#define B_AX_CCK_CCA_TIMEOUT_INT_EN BIT(1)
#define B_AXC_PHY_TXON_TIMEOUT_INT_EN BIT(0)

#define R_AX_PHYINFO_ERR_ISR 0xCCFF
#define R_AX_PHYINFO_ERR_ISR_C1 0xECFF

#define R_AX_DLK_PROTECT_CTL 0xCE02
#define R_AX_DLK_PROTECT_CTL_C1 0xEE02
#define B_AX_RX_DLK_CCA_TIME_MASK GENMASK(15, 8)
#define B_AX_RX_DLK_DATA_TIME_MASK GENMASK(7, 4)

#define R_AX_PLCP_HDR_FLTR 0xCE04
#define R_AX_PLCP_HDR_FLTR_C1 0xEE04
#define B_AX_DIS_CHK_MIN_LEN BIT(8)
#define B_AX_HE_SIGB_CRC_CHK BIT(4)
#define B_AX_VHT_MU_SIGB_CRC_CHK BIT(3)
#define B_AX_VHT_SU_SIGB_CRC_CHK BIT(2)
#define B_AX_SIGA_CRC_CHK BIT(1)
#define B_AX_CCK_CRC_CHK BIT(0)

#define R_AX_RX_FLTR_OPT 0xCE20
#define R_AX_RX_FLTR_OPT_C1 0xEE20
#define B_AX_UID_FILTER_MASK GENMASK(31, 24)
#define B_AX_UNSPT_FILTER_SH 22
#define B_AX_UNSPT_FILTER_MASK GENMASK(23, 22)
#define B_AX_RX_MPDU_MAX_LEN_MASK GENMASK(21, 16)
#define B_AX_A_FTM_REQ BIT(14)
#define B_AX_A_ERR_PKT BIT(13)
#define B_AX_A_UNSUP_PKT BIT(12)
#define B_AX_A_CRC32_ERR BIT(11)
#define B_AX_A_PWR_MGNT BIT(10)
#define B_AX_A_BCN_CHK_RULE_MASK GENMASK(9, 8)
#define B_AX_A_BCN_CHK_EN BIT(7)
#define B_AX_A_MC_LIST_CAM_MATCH BIT(6)
#define B_AX_A_BC_CAM_MATCH BIT(5)
#define B_AX_A_UC_CAM_MATCH BIT(4)
#define B_AX_A_MC BIT(3)
#define B_AX_A_BC BIT(2)
#define B_AX_A_A1_MATCH BIT(1)
#define B_AX_SNIFFER_MODE BIT(0)

#define R_AX_CTRL_FLTR 0xCE24
#define R_AX_CTRL_FLTR_C1 0xEE24
#define R_AX_MGNT_FLTR 0xCE28
#define R_AX_MGNT_FLTR_C1 0xEE28
#define R_AX_DATA_FLTR 0xCE2C
#define R_AX_DATA_FLTR_C1 0xEE2C
#define RX_FLTR_FRAME_DROP	0x00000000
#define RX_FLTR_FRAME_TO_HOST	0x55555555
#define RX_FLTR_FRAME_TO_WLCPU	0xAAAAAAAA

#define R_AX_ADDR_CAM_CTRL 0xCE34
#define R_AX_ADDR_CAM_CTRL_C1 0xEE34
#define B_AX_ADDR_CAM_RANGE_MASK GENMASK(23, 16)
#define B_AX_ADDR_CAM_CMPLIMT_MASK GENMASK(15, 12)
#define B_AX_ADDR_CAM_CLR BIT(8)
#define B_AX_ADDR_CAM_A2_B0_CHK BIT(2)
#define B_AX_ADDR_CAM_SRCH_PERPKT BIT(1)
#define B_AX_ADDR_CAM_EN BIT(0)

#define R_AX_RESPBA_CAM_CTRL 0xCE3C
#define R_AX_RESPBA_CAM_CTRL_C1 0xEE3C
#define B_AX_SSN_SEL BIT(2)

#define R_AX_RX_SR_CTRL 0xCE4A
#define R_AX_RX_SR_CTRL_C1 0xEE4A
#define B_AX_SR_EN BIT(0)

#define R_AX_RX_STATE_MONITOR 0xCEF0
#define R_AX_RX_STATE_MONITOR_C1 0xEEF0
#define R_AX_RX_STATE_MONITOR_MSK GENMASK(31, 0)
#define B_AX_STATE_CUR GENMASK(31, 16)
#define B_AX_STATE_NXT GENMASK(13, 8)
#define B_AX_STATE_UPD BIT(7)
#define B_AX_STATE_SEL GENMASK(4, 0)

#define R_AX_RMAC_ERR_ISR 0xCEF4
#define R_AX_RMAC_ERR_ISR_C1 0xEEF4

#define R_AX_RMAC_PLCP_MON 0xCEF8
#define R_AX_RMAC_PLCP_MON_C1 0xEEF8
#define R_AX_RMAC_PLCP_MON_MSK GENMASK(31, 0)
#define B_AX_PCLP_MON_SEL GENMASK(31, 28)
#define B_AX_PCLP_MON_CONT GENMASK(27, 0)

#define R_AX_RX_DEBUG_SELECT 0xCEFC
#define R_AX_RX_DEBUG_SELECT_C1 0xEEFC
#define B_AX_DEBUG_SEL GENMASK(7, 0)

#define R_AX_TXPWR_ISR 0xD9E4
#define R_AX_TXPWR_ISR_C1 0xF9E4

#endif
