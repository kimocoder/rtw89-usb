// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include "core.h"
#include "phy.h"
#include "rtw8852a_table.h"


static const u32 rtw8852a_bb[] = {
	0x0804, 0x601e0100,
	0x0884, 0x601e0100,
	0x0814, 0x00000000,
	0x0818, 0x13332333,
	0x0814, 0x00010000,
	0x0820, 0x20000000,
	0x08a0, 0x20000000,
	0x1000, 0x00000000,
	0x1004, 0xca014000,
	0x1008, 0xc751d4f0,
	0x100c, 0x44511475,
	0x1010, 0x00000000,
	0x1014, 0x00000000,
	0x1018, 0x00000000,
	0x101c, 0x00000001,
	0x1020, 0x8c30c30c,
	0x1024, 0x4c30c30c,
	0x1028, 0x0c30c30c,
	0x102c, 0x0c30c30c,
	0x1030, 0x0c30c30c,
	0x1034, 0x0c30c30c,
	0x1038, 0x28a28a28,
	0x103c, 0x28a28a28,
	0x1040, 0x28a28a28,
	0x1044, 0x28a28a28,
	0x1048, 0x28a28a28,
	0x104c, 0x28a28a28,
	0x1050, 0x06666666,
	0x1054, 0x33333333,
	0x1058, 0x33333333,
	0x105c, 0x33333333,
	0x1060, 0x00000031,
	0x1064, 0x5100600a,
	0x1068, 0x18363113,
	0x106c, 0x1d976ddc,
	0x1070, 0x1c072dd7,
	0x1074, 0x1127cdf4,
	0x1078, 0x1e37bdf1,
	0x107c, 0x1fb7f1d6,
	0x1080, 0x1ea7ddf9,
	0x1084, 0x1fe445dd,
	0x1088, 0x1f97f1fe,
	0x108c, 0x1ff781ed,
	0x1090, 0x1fa7f5fe,
	0x1094, 0x1e07b913,
	0x1098, 0x1fd7fdff,
	0x109c, 0x1e17b9fa,
	0x10a0, 0x19a66914,
	0x10a4, 0x10f65598,
	0x10a8, 0x14a5a111,
	0x10ac, 0x1d3765db,
	0x10b0, 0x17c685ca,
	0x10b4, 0x1107c5f3,
	0x10b8, 0x1b5785eb,
	0x10bc, 0x1f97ed8f,
	0x10c0, 0x1bc7a5f3,
	0x10c4, 0x1fe43595,
	0x10c8, 0x1eb7d9fc,
	0x10cc, 0x1fe65dbe,
	0x10d0, 0x1ec7d9fc,
	0x10d4, 0x1976fcff,
	0x10d8, 0x1f77f5ff,
	0x10dc, 0x1976fdec,
	0x10e0, 0x198664ef,
	0x10e4, 0x11062d93,
	0x10e8, 0x10c4e910,
	0x10ec, 0x1ca759db,
	0x10f0, 0x1335a9b5,
	0x10f4, 0x1097b9f3,
	0x10f8, 0x17b72de1,
	0x10fc, 0x1f67ed42,
	0x1100, 0x18074de9,
	0x1104, 0x1fd40547,
	0x1108, 0x1d57adf9,
	0x110c, 0x1fe52182,
	0x1110, 0x1d67b1f9,
	0x1114, 0x14860ce1,
	0x1118, 0x1ec7e9fe,
	0x111c, 0x14860dd6,
	0x1120, 0x195664c7,
	0x1124, 0x0005e58a,
	0x1128, 0x00000000,
	0x112c, 0x00000000,
	0x1130, 0x7a000000,
	0x1134, 0x0f9f3d7a,
	0x1138, 0x0040817c,
	0x113c, 0x00e10204,
	0x1140, 0x227d94cd,
	0x1144, 0x084238e3,
	0x1148, 0x00000010,
	0x114c, 0x0011a200,
	0x1150, 0x0060b002,
	0x1154, 0x9a8249a8,
	0x1158, 0x26a1469e,
	0x115c, 0x2099a824,
	0x1160, 0x2359461c,
	0x1164, 0x1631a675,
	0x1168, 0x2c6b1d63,
	0x116c, 0x0000000e,
	0x1170, 0x00000001,
	0x1174, 0x00000001,
	0x1178, 0x00000000,
	0x117c, 0x0000000c,
	0x1180, 0x00000000,
	0x1184, 0x00000000,
	0x1188, 0x0418317c,
	0x118c, 0x00d6135c,
	0x1190, 0x00000000,
	0x1194, 0x00000000,
	0x1198, 0x00000000,
	0x119c, 0x00000000,
	0x11a0, 0x00000000,
	0x11a4, 0x00000000,
	0x11a8, 0x00000000,
	0x11ac, 0x00000000,
	0x11b0, 0x00000000,
	0x11b4, 0xb4026000,
	0x11b8, 0x00000960,
	0x11bc, 0x02024008,
	0x11c0, 0x00000000,
	0x11c4, 0x00000000,
	0x11c8, 0x22ce803c,
	0x11cc, 0x32000000,
	0x11d0, 0xbd67d67d,
	0x11d4, 0x02aaaf59,
	0x11d8, 0x00000000,
	0x11dc, 0x00000000,
	0x11e0, 0x00000004,
	0x11e4, 0x00000001,
	0x11e8, 0x61861800,
	0x11ec, 0x830c30c3,
	0x11f0, 0xc30c30c3,
	0x11f4, 0x830c30c3,
	0x11f8, 0x051450c3,
	0x11fc, 0x05145145,
	0x1200, 0x05145145,
	0x1204, 0x05145145,
	0x1208, 0x0f0c3145,
	0x120c, 0x030c30cf,
	0x1210, 0x030c30c3,
	0x1214, 0x030cf3c3,
	0x1218, 0x030c30c3,
	0x121c, 0x0f3cf3c3,
	0x1220, 0x0f3cf3cf,
	0x1224, 0x0f3cf3cf,
	0x1228, 0x0f3cf3cf,
	0x122c, 0x0f3cf3cf,
	0x1230, 0x030c10c3,
	0x1234, 0x051430c3,
	0x1238, 0x051490cb,
	0x123c, 0x030cd151,
	0x1240, 0x050c50c7,
	0x1244, 0x051492cb,
	0x1248, 0x05145145,
	0x124c, 0x05145145,
	0x1250, 0x05145145,
	0x1254, 0x05145145,
	0x1258, 0x090cd3cf,
	0x125c, 0x071491c5,
	0x1260, 0x073cf143,
	0x1264, 0x071431c3,
	0x1268, 0x0f3cf1c5,
	0x126c, 0x0f3cf3cf,
	0x1270, 0x0f3cf3cf,
	0x1274, 0x0f3cf3cf,
	0x1278, 0x0f3cf3cf,
	0x127c, 0x090c91cf,
	0x1280, 0x11243143,
	0x1284, 0x9777a777,
	0x1288, 0xbb7bac95,
	0x128c, 0xb667b889,
	0x1290, 0x7b9b8899,
	0x1294, 0x7a5567c8,
	0x1298, 0x2278cccc,
	0x129c, 0x00037c22,
	0x12a0, 0x001ccccc,
	0x12a4, 0x00000000,
	0x12a8, 0x00000008,
	0x12ac, 0x00000000,
	0x12b0, 0x00000000,
	0x12b4, 0x00000000,
	0x12b8, 0x10000800,
	0x12bc, 0x00401802,
	0x12c0, 0x00061004,
	0x12c4, 0x000024d8,
	0x12c8, 0x10000020,
	0x12cc, 0x20000200,
	0x12d0, 0x00000000,
	0x12d4, 0x04000000,
	0x12d8, 0x44000100,
	0x12dc, 0x60804060,
	0x12e0, 0x44204210,
	0x12e4, 0x82108082,
	0x12e8, 0x82108402,
	0x12ec, 0xc8082108,
	0x12f0, 0x48202084,
	0x12f4, 0x44208208,
	0x12f8, 0x84108204,
	0x12fc, 0xd0108104,
	0x1300, 0xf8210108,
	0x1304, 0x6431e930,
	0x1308, 0x02109468,
	0x130c, 0x10c61c22,
	0x1310, 0x02109469,
	0x1314, 0x10c61c22,
	0x1318, 0x00041049,
	0x131c, 0x00000000,
	0x1320, 0x00000000,
	0x1324, 0xa0000000,
	0x1328, 0x04204000,
	0x132c, 0x00000000,
	0x1330, 0x00000000,
	0x1334, 0x00000000,
	0x1338, 0x00000000,
	0x133c, 0x25f64320,
	0x1340, 0xa80668a0,
	0x1344, 0x60900820,
	0x1348, 0xa108598c,
	0x134c, 0x32488a62,
	0x1350, 0x9c6e36dc,
	0x1354, 0x0000b50b,
	0x1358, 0x00000000,
	0x135c, 0x0801442e,
	0x1360, 0x000120b8,
	0x1364, 0x00000000,
	0x1368, 0x00000000,
	0x136c, 0x00000000,
	0x1370, 0x00000000,
	0x1374, 0x00000000,
	0x1378, 0x2a0a6040,
	0x137c, 0x0a0a6829,
	0x1380, 0x00000004,
	0x1384, 0x00000000,
	0x1388, 0x80000000,
	0x138c, 0x10000000,
	0x1390, 0xa0000000,
	0x1394, 0x0000001e,
	0x1398, 0x00018614,
	0x139c, 0x00000001,
	0x13a0, 0x00000001,
	0x13a4, 0x00000000,
	0x13a8, 0x00000000,
	0x13ac, 0x00000000,
	0x13b0, 0x00000000,
	0x13b4, 0x00000000,
	0x13b8, 0x00000000,
	0x13bc, 0x00000000,
	0x13c0, 0x00000000,
	0x13c4, 0x00000000,
	0x13c8, 0x00000000,
	0x13cc, 0x00000000,
	0x13d0, 0x00000000,
	0x13d4, 0x00000000,
	0x13d8, 0x00000000,
	0x13dc, 0x00000000,
	0x13e0, 0x00000000,
	0x13e4, 0x00000000,
	0x13e8, 0x00000000,
	0x13ec, 0x00000000,
	0x13f0, 0x00000000,
	0x13f4, 0x00000000,
	0x13f8, 0x00000000,
	0x13fc, 0x00000000,
	0x1400, 0x00000000,
	0x1404, 0x00000000,
	0x1408, 0x00000000,
	0x140c, 0x00000000,
	0x1410, 0x00000000,
	0x1414, 0x00000000,
	0x1418, 0x00000000,
	0x141c, 0x00000000,
	0x1420, 0x00000000,
	0x1424, 0x4ea20631,
	0x1428, 0x000005c8,
	0x142c, 0x000000ff,
	0x1430, 0x00000000,
	0x1434, 0x00000000,
	0x1438, 0x00000000,
	0x143c, 0x00000000,
	0x1440, 0x00000000,
	0x1444, 0x00000000,
	0x1448, 0x00000000,
	0x144c, 0x00000000,
	0x1450, 0x00000000,
	0x1454, 0x4060001a,
	0x1458, 0x40000000,
	0x145c, 0x00000000,
	0x1460, 0x20000000,
	0x1464, 0x00800406,
	0x1468, 0x00022270,
	0x146c, 0x0002024b,
	0x1470, 0x00009b40,
	0x1474, 0x00000000,
	0x1478, 0x00000063,
	0x147c, 0x30000000,
	0x1480, 0x00000001,
	0x1484, 0x02800000,
	0x1488, 0xe0000800,
	0x148c, 0x03fc0000,
	0x1490, 0x00000001,
	0x1494, 0x00000000,
	0x1498, 0x00000700,
	0x149c, 0x00500000,
	0x14a0, 0xc0000048,
	0x14a4, 0x1c909200,
	0x14a8, 0x00000010,
	0x14ac, 0x00000000,
	0x14b0, 0x00f20006,
	0x14b4, 0x000000e9,
	0x14b8, 0x00000000,
	0x14bc, 0x00000000,
	0x14c0, 0x000ce000,
	0x14c4, 0x0007e0ab,
	0x14c8, 0x00024051,
	0x14cc, 0x00000012,
	0x14d0, 0x00000000,
	0x14d4, 0x1212100b,
	0x14d8, 0x00000006,
	0x14dc, 0x00000000,
	0x14e0, 0x00000872,
	0x14e4, 0x00000003,
	0x14e8, 0x000003d9,
	0x18d0, 0x00000000,
	0x18d4, 0x00000001,
	0x14ec, 0x00000000,
	0x14f0, 0x00000001,
	0x14f4, 0x25294992,
	0x14f8, 0x1ce62a52,
	0x14fc, 0x1cf739ce,
	0x1500, 0x5ce739ce,
	0x1504, 0x0002908e,
	0x1508, 0x00000001,
	0x150c, 0x00000077,
	0x1510, 0x00000028,
	0x1514, 0x00000004,
	0x1518, 0x00000000,
	0x151c, 0x00000000,
	0x1520, 0x00e2e100,
	0x1524, 0xcb00b6b6,
	0x1528, 0x59100fca,
	0x152c, 0x08882550,
	0x1530, 0x08cc2660,
	0x1534, 0x09102660,
	0x1538, 0x00000154,
	0x153c, 0x31bf0400,
	0x1540, 0x2c4e346d,
	0x1544, 0x3d7c6d6d,
	0x1548, 0x009cfdf0,
	0x154c, 0xe2003f80,
	0x1550, 0x02ca8d00,
	0x1554, 0x41e7f306,
	0x1558, 0x75dc3e3a,
	0x155c, 0xb136eece,
	0x1560, 0xbfbf41b2,
	0x1564, 0x78910d36,
	0x1568, 0xb7c5fef8,
	0x156c, 0x2a72ad17,
	0x1570, 0xc2544fb2,
	0x1574, 0x50823404,
	0x1578, 0xbe84bc00,
	0x157c, 0x9889314f,
	0x1580, 0x5ecc7ff4,
	0x1584, 0x6388ecae,
	0x1588, 0xf8434706,
	0x158c, 0x6505d59a,
	0x1590, 0x5b6d6494,
	0x1594, 0x5ce6c5b6,
	0x1598, 0x05467f3d,
	0x18a8, 0xf9d7ba9f,
	0x18ac, 0x4f563411,
	0x18b0, 0x00000067,
	0x18c0, 0x00000009,
	0x18c8, 0x00000008,
	0x159c, 0x00000000,
	0x15a0, 0x00000000,
	0x15a4, 0x00000219,
	0x15a8, 0x00000000,
	0x15ac, 0x00000000,
	0x15b0, 0x00000001,
	0x15b4, 0x00000001,
	0x15b8, 0x00000000,
	0x15bc, 0x00000000,
	0x15c0, 0x00000151,
	0x15c4, 0x00000498,
	0x15c8, 0x00000498,
	0x15cc, 0x00000000,
	0x15d0, 0x00000000,
	0x15d4, 0x000013c6,
	0x15d8, 0x00000000,
	0x15dc, 0x00000000,
	0x15e0, 0x00e2e100,
	0x15e4, 0xcb00b6b6,
	0x15e8, 0x59100fca,
	0x15ec, 0x08882550,
	0x15f0, 0x08cc2660,
	0x15f4, 0x09102660,
	0x15f8, 0x00000154,
	0x15fc, 0x31bf0400,
	0x1600, 0x2c4e346d,
	0x1604, 0x3d7c6d6d,
	0x1608, 0x009cfdf0,
	0x160c, 0xe2003f80,
	0x1610, 0x02ca8d00,
	0x1614, 0x41e7e306,
	0x1618, 0x75dc3e39,
	0x161c, 0xb136eece,
	0x1620, 0xbfbf31b2,
	0x1624, 0x78910d35,
	0x1628, 0xb7c5fef8,
	0x162c, 0x2a72ad17,
	0x1630, 0xc2544fb2,
	0x1634, 0x50823404,
	0x1638, 0xbe84bc00,
	0x163c, 0x9889314f,
	0x1640, 0x5ecc7ff4,
	0x1644, 0x6388ecae,
	0x1648, 0xf8434706,
	0x164c, 0x6505d59a,
	0x1650, 0x5b6d6494,
	0x1654, 0x5ce6c5b6,
	0x1658, 0x05467f3d,
	0x18b4, 0xf9d7b99e,
	0x18b8, 0x4f553311,
	0x18bc, 0x00000067,
	0x18c4, 0x00000009,
	0x18cc, 0x00000008,
	0x165c, 0x00000000,
	0x1660, 0x00000000,
	0x1664, 0x00000219,
	0x1668, 0x00000000,
	0x166c, 0x00000000,
	0x1670, 0x00000001,
	0x1674, 0x00000001,
	0x1678, 0x00000000,
	0x167c, 0x00000000,
	0x1680, 0x00000151,
	0x1684, 0x00000498,
	0x1688, 0x00000498,
	0x168c, 0x00000000,
	0x1690, 0x00000000,
	0x1694, 0x000013c6,
	0x1698, 0xe32103fe,
	0x169c, 0xb20a7b28,
	0x16a0, 0xc6a7b14f,
	0x16a4, 0x0000003b,
	0x16a8, 0x009b902a,
	0x16ac, 0x009b902a,
	0x16b0, 0x98682c18,
	0x16b4, 0x6308c4c1,
	0x16b8, 0x6248c631,
	0x16bc, 0x922a8253,
	0x16c0, 0x00000005,
	0x16c4, 0x00001759,
	0x16c8, 0x4b802000,
	0x16cc, 0x831408be,
	0x16d0, 0x9ABBCACB,
	0x16d4, 0x56767578,
	0x16d8, 0xBBCCBBB3,
	0x16dc, 0x57887789,
	0x16e0, 0x00000F45,
	0x16e4, 0x27039ce9,
	0x16e8, 0x31413432,
	0x16ec, 0x62658342,
	0x16f0, 0x00000005,
	0x16f4, 0x00000005,
	0x16f8, 0xc7013016,
	0x16fc, 0x84413016,
	0x1700, 0x84413016,
	0x1704, 0x8c413016,
	0x1708, 0x8c40b028,
	0x170c, 0x3140b028,
	0x1710, 0x2940b028,
	0x1714, 0x8440b028,
	0x1718, 0x2318c610,
	0x171c, 0x45334753,
	0x1720, 0x236a6a88,
	0x1724, 0x576df814,
	0x1728, 0xa08877ac,
	0x172c, 0x0000007a,
	0x1730, 0xbceb4a14,
	0x1734, 0x000a3a4a,
	0x1738, 0xbceb4a14,
	0x173c, 0x000a3a4a,
	0x1740, 0xBCBDAC97,
	0x1744, 0x0CABB99A,
	0x1748, 0x38384242,
	0x174c, 0x0086402e,
	0x1750, 0x06e066aa,
	0x1754, 0x00008a62,
	0x1758, 0x00000008,
	0x175c, 0x009b902a,
	0x1760, 0x009b902a,
	0x1764, 0x98682c18,
	0x1768, 0x6308c4c1,
	0x176c, 0x6248c631,
	0x1770, 0x922a8253,
	0x1774, 0x00000005,
	0x1778, 0x00001759,
	0x177c, 0x4b802000,
	0x1780, 0x831408be,
	0x1784, 0x9898a8bb,
	0x1788, 0x54535368,
	0x178c, 0x999999b3,
	0x1790, 0x35555589,
	0x1794, 0x00000745,
	0x1798, 0x27039ce9,
	0x179c, 0x31413432,
	0x17a0, 0x62658342,
	0x17a4, 0x00000005,
	0x17a8, 0x00000005,
	0x17ac, 0xc7013016,
	0x17b0, 0x84413016,
	0x17b4, 0x84413016,
	0x17b8, 0x8c413016,
	0x17bc, 0x8c40b028,
	0x17c0, 0x3140b028,
	0x17c4, 0x2940b028,
	0x17c8, 0x8440b028,
	0x17cc, 0x2318c610,
	0x17d0, 0x45334753,
	0x17d4, 0x236a6a88,
	0x17d8, 0x576df814,
	0x17dc, 0xa08877ac,
	0x17e0, 0x0000007a,
	0x17e4, 0xbceb4a14,
	0x17e8, 0x000a3a4a,
	0x17ec, 0xbceb4a14,
	0x17f0, 0x000a3a4a,
	0x17f4, 0x9a8a8a97,
	0x17f8, 0x0ca3b99a,
	0x17fc, 0x38384242,
	0x1800, 0x0086402e,
	0x1804, 0x06e066aa,
	0x1808, 0x00008a62,
	0x180c, 0x00000008,
	0x1810, 0x80040000,
	0x1814, 0x80040000,
	0x1818, 0xfe800000,
	0x181c, 0x834c0000,
	0x1820, 0x00000000,
	0x1824, 0x00000000,
	0x1828, 0x00000000,
	0x182c, 0x00000000,
	0x1830, 0x00000000,
	0x1834, 0x00000000,
	0x1838, 0x00000000,
	0x183c, 0x00000000,
	0x1840, 0x00000000,
	0x1844, 0x00000000,
	0x1848, 0x00000000,
	0x184c, 0x04065800,
	0x1850, 0x12010080,
	0x1854, 0x0e1e3e05,
	0x1858, 0x0a163068,
	0x185c, 0x00206040,
	0x1860, 0x02020202,
	0x1864, 0x0fbf6020,
	0x1868, 0x011f7efc,
	0x186c, 0x0fbf3efd,
	0x1870, 0x0000007d,
	0x1874, 0x00000000,
	0x1878, 0x800cd62d,
	0x187c, 0x00000103,
	0x1880, 0x00000000,
	0x1884, 0x00000000,
	0x1888, 0x00000000,
	0x188c, 0x00000000,
	0x1890, 0x00000000,
	0x1894, 0x00000000,
	0x1898, 0x00000000,
	0x189c, 0x00000000,
	0x18a0, 0x00000000,
	0x18a4, 0x00000000,
	0x0d80, 0x10002250,
	0x0dc0, 0x10002250,
	0x0d14, 0x3c3c4100,
	0x0dd4, 0x3c3c4110,
	0x1454, 0x4060001a,
	0x0244, 0x2314283c,
	0x0244, 0x2323283c,
	0x0d94, 0x00000010,
	0x0a3c, 0x2840e1bf,
	0x0a40, 0x00000000,
	0x0a44, 0x00000007,
	0x0a48, 0x410e4000,
	0x0a54, 0x1001436e,
	0x0a58, 0x41000000,
	0x0830, 0x00000002,
	0x0a60, 0x017ffff2,
	0x0a64, 0x0010a130,
	0x0a64, 0x0010a130,
	0x0a68, 0x000000ff,
	0x0a64, 0x0010a130,
	0x0a54, 0x1001436e,
	0x0a6c, 0x00000020,
	0x0808, 0x00000000,
	0x0a6c, 0x00000020,
	0x0f84, 0x0043f01d,
	0x4cd0, 0x00000000,
	0x4cec, 0x888ca72b,
	0x4dd0, 0x00000000,
	0x4dec, 0x888ca72b,
	0x4540, 0x76582bf7,
	0x4544, 0x00104630,
	0x4548, 0x0000fffc,
	0x454c, 0x00000000,
	0x4550, 0x00000000,
	0x4554, 0x00000035,
	0x4558, 0x00000000,
	0x455c, 0x00000000,
	0x4560, 0x00000000,
	0x4564, 0x00000000,
	0x4570, 0x00000000,
	0x4590, 0x000003ff,
	0x4594, 0x00000000,
	0x4598, 0x0000003f,
	0x459c, 0x00000000,
	0x45a0, 0x00000000,
	0x45a4, 0x00000000,
	0x45a8, 0x00000000,
	0x45ac, 0x00000000,
	0x4500, 0x77777777,
	0x4504, 0x99999999,
	0x4508, 0x99999999,
	0x450c, 0x00000070,
	0x4510, 0x20110900,
	0x4510, 0x20110fff,
	0x457c, 0x001c0408,
	0x4584, 0x00000007,
	0x4518, 0x50209d00,
	0x4580, 0x00804100,
	0x0814, 0x0001004f,
	0x0804, 0x601e00fd,
	0x0810, 0xef810000,
	0x0884, 0x601e0100,
	0x0890, 0xef810000,
	0x0000, 0x0580801f,
	0x0000, 0x8580801f,
	0x0b34, 0xffffffff,
	0x0b3c, 0x55000000,
	0x0b40, 0x00005555,
	0x0824, 0x00111201,
	0x7c68, 0xa9550000,
	0x7c70, 0x33221100,
	0x7c74, 0x77665544,
	0x7c78, 0xbbaa9988,
	0x7c7c, 0xffeeddcc,
	0x7c80, 0x76543210,
	0x7c84, 0xfedcba98,
	0x7c88, 0x00000000,
	0x7c8c, 0x00000000,
	0x7c94, 0x00000008,
	0x7d68, 0xa9550000,
	0x7d70, 0x33221100,
	0x7d74, 0x77665544,
	0x7d78, 0xbbaa9988,
	0x7d7c, 0xffeeddcc,
	0x7d80, 0x76543210,
	0x7d84, 0xfedcba98,
	0x7d88, 0x00000000,
	0x7d8c, 0x00000000,
	0x7d94, 0x00000008,
	0x0e0c, 0x00000000,
	0x7800, 0x02748790,
	0x7804, 0x00558670,
	0x7808, 0x002883f0,
	0x780c, 0x00090120,
	0x7810, 0x00000000,
	0x7814, 0x06000000,
	0x7818, 0x00000000,
	0x781c, 0x00000000,
	0x7820, 0x03020100,
	0x7824, 0x07060504,
	0x7828, 0x0b0a0908,
	0x782c, 0x0f0e0d0c,
	0x7830, 0x13121110,
	0x7834, 0x17161514,
	0x7838, 0x0c700022,
	0x783c, 0x0a05298f,
	0x7840, 0x0005296e,
	0x7844, 0x0006318a,
	0x7848, 0xa006318a,
	0x784c, 0x80039ca7,
	0x7850, 0x80039ca7,
	0x7854, 0x0005298f,
	0x7858, 0x0015296e,
	0x785c, 0x0c07fc31,
	0x7860, 0x0219a6ae,
	0x7864, 0xe4f624c3,
	0x7868, 0x53626f15,
	0x786c, 0x48000000,
	0x7870, 0x48000000,
	0x7874, 0x034c0000,
	0x7878, 0x202401b0,
	0x787c, 0x00f70016,
	0x7880, 0x0f0a1111,
	0x7884, 0x30c9000f,
	0x7888, 0x0400ea02,
	0x788c, 0x003cb061,
	0x7890, 0x69c00000,
	0x7894, 0x00000000,
	0x7898, 0x000000f0,
	0x789c, 0x0001ffff,
	0x78a0, 0x00c80064,
	0x78a4, 0x0190012c,
	0x78a8, 0x001917fe,
	0x78ac, 0x07308a00,
	0x78b0, 0x0001ce00,
	0x78b4, 0x00027c00,
	0x0a70, 0x00000400,
	0x0800, 0x00000030,
	0x0804, 0x601e00ff,
	0x0884, 0x601e0102,
	0x0804, 0x601e00fd,
	0x0884, 0x601e0100,
	0x0804, 0x601e00ff,
	0x0884, 0x601e0102,
	0x7c6c, 0x000000f0,
	0x7c6c, 0x000000e0,
	0x7c6c, 0x000000d0,
	0x7c6c, 0x000000c0,
	0x7c6c, 0x000000b0,
	0x7c6c, 0x000000a0,
	0x7c6c, 0x00000090,
	0x7c6c, 0x00000080,
	0x7c6c, 0x00000070,
	0x7c6c, 0x00000060,
	0x7c6c, 0x00000050,
	0x7c6c, 0x00000040,
	0x7c6c, 0x00000030,
	0x7c6c, 0x00000020,
	0x7c6c, 0x00000010,
	0x7c6c, 0x00000000,
	0x7d6c, 0x000000f0,
	0x7d6c, 0x000000e0,
	0x7d6c, 0x000000d0,
	0x7d6c, 0x000000c0,
	0x7d6c, 0x000000b0,
	0x7d6c, 0x000000a0,
	0x7d6c, 0x00000090,
	0x7d6c, 0x00000080,
	0x7d6c, 0x00000070,
	0x7d6c, 0x00000060,
	0x7d6c, 0x00000050,
	0x7d6c, 0x00000040,
	0x7d6c, 0x00000030,
	0x7d6c, 0x00000020,
	0x7d6c, 0x00000010,
	0x7d6c, 0x00000000,
	0x7c64, 0x080801ff,
	0x7d64, 0x080801ff,
	0x0a60, 0x017ffff3,
	0x0a6c, 0x00000021,
	0x7cac, 0x08000000,
	0x7dac, 0x08000000,
	0x7c64, 0x180801ff,
	0x7d64, 0x180801ff,
	0x0a60, 0x017ffff3,
	0x0a60, 0x017ffffb,
	0x0ae0, 0x013fff0a,
	0x0a70, 0x00000600,
	0x0a70, 0x00000660,
	0x0a6c, 0x00000021,
	0x7cac, 0x08000000,
	0x7dac, 0x08000000,
	0x7c64, 0x100801ff,
	0x7d64, 0x100801ff,
	0x7c64, 0x000801ff,
	0x7d64, 0x000801ff,
	0x0804, 0x601e01ff,
	0x0884, 0x601e0102,
	0x7cd4, 0x3401fe00,
	0x7dd4, 0x3401fe00,
	0x7cf0, 0x000401ff,
	0x7df0, 0x000401ff,
	0x7cf0, 0x400401ff,
	0x7df0, 0x400401ff,
	0x4ca8, 0x333378a5,
	0x4da8, 0x333378a5,
	0x7800, 0x02748790,
	0x7804, 0x00558670,
	0x7808, 0x002883f0,
	0x780c, 0x00090120,
	0x7810, 0x00000000,
	0x7814, 0x06000000,
	0x7818, 0x00000000,
	0x781c, 0x00000000,
	0x7820, 0x03020100,
	0x7824, 0x07060504,
	0x7828, 0x0b0a0908,
	0x782c, 0x0f0e0d0c,
	0x7830, 0x13121110,
	0x7834, 0x17161514,
	0x7838, 0x0c700022,
	0x783c, 0x0a05298f,
	0x7840, 0x0005296e,
	0x7844, 0x0006318a,
	0x7848, 0xa006318a,
	0x784c, 0x80039ce7,
	0x7850, 0x80039ce7,
	0x7854, 0x0005298f,
	0x7858, 0x0015296e,
	0x785c, 0x0c07fc31,
	0x7860, 0x0299a6ae,
	0x7864, 0xe4f624c3,
	0x7868, 0x53626f15,
	0x786c, 0x48000000,
	0x7870, 0x48000000,
	0x7874, 0x034c0000,
	0x7878, 0x202401b0,
	0x787c, 0x00f70016,
	0x7880, 0x0f0a1111,
	0x7884, 0x30c9000f,
	0x7888, 0x0000ea02,
	0x788c, 0x003cb061,
	0x7890, 0x69c00000,
	0x7894, 0x00000000,
	0x7898, 0x000000f0,
	0x789c, 0x0001ffff,
	0x78a0, 0x00c80064,
	0x78a4, 0x0190012c,
	0x78a8, 0x001917de,
	0x78ac, 0x07308A00,
	0x78b0, 0x000BF800,
	0x78b4, 0x00057400,
	0x78b8, 0x00000000,
	0x78bc, 0x00000000,
	0x78c0, 0x00000000,
	0x78c4, 0x00000000,
	0x78c8, 0x00000000,
	0x78cc, 0x00000000,
	0x78d0, 0x00000000,
	0x78d4, 0x00000000,
	0x78d8, 0x00000000,
	0x78dc, 0x00000000,
	0x78e0, 0x00000000,
	0x78e4, 0x00000000,
	0x78e8, 0x00000000,
	0x78ec, 0x00000000,
	0x78f0, 0x00000000,
	0x78f4, 0x00000000,
	0x78f8, 0x00000000,
	0x78fc, 0x00000000,
	0x0894, 0x00000000,
	0x0898, 0x13332333,
	0x0894, 0x00010000,
	0x5000, 0x00000000,
	0x5004, 0xca014000,
	0x5008, 0xc751d4f0,
	0x500c, 0x44511475,
	0x5010, 0x00000000,
	0x5014, 0x00000000,
	0x5018, 0x00000000,
	0x501c, 0x00000001,
	0x5020, 0x8c30c30c,
	0x5024, 0x4c30c30c,
	0x5028, 0x0c30c30c,
	0x502c, 0x0c30c30c,
	0x5030, 0x0c30c30c,
	0x5034, 0x0c30c30c,
	0x5038, 0x28a28a28,
	0x503c, 0x28a28a28,
	0x5040, 0x28a28a28,
	0x5044, 0x28a28a28,
	0x5048, 0x28a28a28,
	0x504c, 0x28a28a28,
	0x5050, 0x06666666,
	0x5054, 0x33333333,
	0x5058, 0x33333333,
	0x505c, 0x33333333,
	0x5060, 0x00000031,
	0x5064, 0x5100600a,
	0x5068, 0x18363113,
	0x506c, 0x1d976ddc,
	0x5070, 0x1c072dd7,
	0x5074, 0x1127cdf4,
	0x5078, 0x1e37bdf1,
	0x507c, 0x1fb7f1d6,
	0x5080, 0x1ea7ddf9,
	0x5084, 0x1fe445dd,
	0x5088, 0x1f97f1fe,
	0x508c, 0x1ff781ed,
	0x5090, 0x1fa7f5fe,
	0x5094, 0x1e07b913,
	0x5098, 0x1fd7fdff,
	0x509c, 0x1e17b9fa,
	0x50a0, 0x19a66914,
	0x50a4, 0x10f65598,
	0x50a8, 0x14a5a111,
	0x50ac, 0x1d3765db,
	0x50b0, 0x17c685ca,
	0x50b4, 0x1107c5f3,
	0x50b8, 0x1b5785eb,
	0x50bc, 0x1f97ed8f,
	0x50c0, 0x1bc7a5f3,
	0x50c4, 0x1fe43595,
	0x50c8, 0x1eb7d9fc,
	0x50cc, 0x1fe65dbe,
	0x50d0, 0x1ec7d9fc,
	0x50d4, 0x1976fcff,
	0x50d8, 0x1f77f5ff,
	0x50dc, 0x1976fdec,
	0x50e0, 0x198664ef,
	0x50e4, 0x11062d93,
	0x50e8, 0x10c4e910,
	0x50ec, 0x1ca759db,
	0x50f0, 0x1335a9b5,
	0x50f4, 0x1097b9f3,
	0x50f8, 0x17b72de1,
	0x50fc, 0x1f67ed42,
	0x5100, 0x18074de9,
	0x5104, 0x1fd40547,
	0x5108, 0x1d57adf9,
	0x510c, 0x1fe52182,
	0x5110, 0x1d67b1f9,
	0x5114, 0x14860ce1,
	0x5118, 0x1ec7e9fe,
	0x511c, 0x14860dd6,
	0x5120, 0x195664c7,
	0x5124, 0x0005e58a,
	0x5128, 0x00000000,
	0x512c, 0x00000000,
	0x5130, 0x7a000000,
	0x5134, 0x0f9f3d7a,
	0x5138, 0x0040817c,
	0x513c, 0x00e10204,
	0x5140, 0x227d94cd,
	0x5144, 0x084238e3,
	0x5148, 0x00000010,
	0x514c, 0x0011a200,
	0x5150, 0x0060b002,
	0x5154, 0x9a8249a8,
	0x5158, 0x26a1469e,
	0x515c, 0x2099a824,
	0x5160, 0x2359461c,
	0x5164, 0x1631a675,
	0x5168, 0x2c6b1d63,
	0x516c, 0x0000000e,
	0x5170, 0x00000001,
	0x5174, 0x00000001,
	0x5178, 0x00000000,
	0x517c, 0x0000000c,
	0x5180, 0x00000000,
	0x5184, 0x00000000,
	0x5188, 0x0418317c,
	0x518c, 0x00d6135c,
	0x5190, 0x00000000,
	0x5194, 0x00000000,
	0x5198, 0x00000000,
	0x519c, 0x00000000,
	0x51a0, 0x00000000,
	0x51a4, 0x00000000,
	0x51a8, 0x00000000,
	0x51ac, 0x00000000,
	0x51b0, 0x00000000,
	0x51b4, 0xb4026000,
	0x51b8, 0x00000960,
	0x51bc, 0x02024008,
	0x51c0, 0x00000000,
	0x51c4, 0x00000000,
	0x51c8, 0x22ce803c,
	0x51cc, 0x32000000,
	0x51d0, 0xbd67d67d,
	0x51d4, 0x02aaaf59,
	0x51d8, 0x00000000,
	0x51dc, 0x00000000,
	0x51e0, 0x00000004,
	0x51e4, 0x00000001,
	0x51e8, 0x61861800,
	0x51ec, 0x830c30c3,
	0x51f0, 0xc30c30c3,
	0x51f4, 0x830c30c3,
	0x51f8, 0x051450c3,
	0x51fc, 0x05145145,
	0x5200, 0x05145145,
	0x5204, 0x05145145,
	0x5208, 0x0f0c3145,
	0x520c, 0x030c30cf,
	0x5210, 0x030c30c3,
	0x5214, 0x030cf3c3,
	0x5218, 0x030c30c3,
	0x521c, 0x0f3cf3c3,
	0x5220, 0x0f3cf3cf,
	0x5224, 0x0f3cf3cf,
	0x5228, 0x0f3cf3cf,
	0x522c, 0x0f3cf3cf,
	0x5230, 0x030c10c3,
	0x5234, 0x051430c3,
	0x5238, 0x051490cb,
	0x523c, 0x030cd151,
	0x5240, 0x050c50c7,
	0x5244, 0x051492cb,
	0x5248, 0x05145145,
	0x524c, 0x05145145,
	0x5250, 0x05145145,
	0x5254, 0x05145145,
	0x5258, 0x090cd3cf,
	0x525c, 0x071491c5,
	0x5260, 0x073cf143,
	0x5264, 0x071431c3,
	0x5268, 0x0f3cf1c5,
	0x526c, 0x0f3cf3cf,
	0x5270, 0x0f3cf3cf,
	0x5274, 0x0f3cf3cf,
	0x5278, 0x0f3cf3cf,
	0x527c, 0x090c91cf,
	0x5280, 0x11243143,
	0x5284, 0x9777a777,
	0x5288, 0xbb7bac95,
	0x528c, 0xb667b889,
	0x5290, 0x7b9b8899,
	0x5294, 0x7a5567c8,
	0x5298, 0x2278cccc,
	0x529c, 0x00037c22,
	0x52a0, 0x001ccccc,
	0x52a4, 0x00000000,
	0x52a8, 0x00000008,
	0x52ac, 0x00000000,
	0x52b0, 0x00000000,
	0x52b4, 0x00000000,
	0x52b8, 0x10000000,
	0x52bc, 0x00401001,
	0x52c0, 0x00061003,
	0x52c4, 0x000024d8,
	0x52c8, 0x10000020,
	0x52cc, 0x20000200,
	0x52d0, 0x00000000,
	0x52d4, 0x04000000,
	0x52d8, 0x44000100,
	0x52dc, 0x60804060,
	0x52e0, 0x44204210,
	0x52e4, 0x82108082,
	0x52e8, 0x82108402,
	0x52ec, 0xc8082108,
	0x52f0, 0x48202084,
	0x52f4, 0x44208208,
	0x52f8, 0x84108204,
	0x52fc, 0xd0108104,
	0x5300, 0xf8210108,
	0x5304, 0x6431e930,
	0x5308, 0x02109468,
	0x530c, 0x10c61c22,
	0x5310, 0x02109469,
	0x5314, 0x10c61c22,
	0x5318, 0x00041049,
	0x531c, 0x00000000,
	0x5320, 0x00000000,
	0x5324, 0xa0000000,
	0x5328, 0x00204000,
	0x532c, 0x00000000,
	0x5330, 0x00000000,
	0x5334, 0x00000000,
	0x5338, 0x00000000,
	0x533c, 0x19064320,
	0x5340, 0xa80668a0,
	0x5344, 0x60900820,
	0x5348, 0xa108598c,
	0x534c, 0x32488a62,
	0x5350, 0x9c6e36dc,
	0x5354, 0x0000b50b,
	0x5358, 0x00000000,
	0x535c, 0x0801442e,
	0x5360, 0x000120b8,
	0x5364, 0x00000000,
	0x5368, 0x00000000,
	0x536c, 0x00000000,
	0x5370, 0x00000000,
	0x5374, 0x00000000,
	0x5378, 0xea0a6040,
	0x537c, 0xfa0a6829,
	0x5380, 0x00000007,
	0x5384, 0x00000000,
	0x5388, 0x80000000,
	0x538c, 0x10000000,
	0x5390, 0xa0000000,
	0x5394, 0x0000001e,
	0x5398, 0x0000c614,
	0x539c, 0x00000001,
	0x53a0, 0x00000001,
	0x53a4, 0x00000000,
	0x53a8, 0x00000000,
	0x53ac, 0x00000000,
	0x53b0, 0x00000000,
	0x53b4, 0x00000000,
	0x53b8, 0x00000000,
	0x53bc, 0x00000000,
	0x53c0, 0x00000000,
	0x53c4, 0x00000000,
	0x53c8, 0x00000000,
	0x53cc, 0x00000000,
	0x53d0, 0x00000000,
	0x53d4, 0x00000000,
	0x53d8, 0x00000000,
	0x53dc, 0x00000000,
	0x53e0, 0x00000000,
	0x53e4, 0x00000000,
	0x53e8, 0x00000000,
	0x53ec, 0x00000000,
	0x53f0, 0x00000000,
	0x53f4, 0x00000000,
	0x53f8, 0x00000000,
	0x53fc, 0x00000000,
	0x5400, 0x00000000,
	0x5404, 0x00000000,
	0x5408, 0x00000000,
	0x540c, 0x00000000,
	0x5410, 0x00000000,
	0x5414, 0x00000000,
	0x5418, 0x00000000,
	0x541c, 0x00000000,
	0x5420, 0x00000000,
	0x5424, 0x4e020f01,
	0x5428, 0x00000168,
	0x542c, 0x000000ff,
	0x5430, 0x00000000,
	0x5434, 0x00000000,
	0x5438, 0x00000000,
	0x543c, 0x00000000,
	0x5440, 0x00000000,
	0x5444, 0x00000000,
	0x5448, 0x00000000,
	0x544c, 0x00000000,
	0x5450, 0x00000000,
	0x5454, 0x4060003d,
	0x5458, 0x40000000,
	0x545c, 0x00000000,
	0x5460, 0x00000000,
	0x5464, 0x00800006,
	0x5468, 0x00011230,
	0x546c, 0x0002036b,
	0x5470, 0x00001640,
	0x5474, 0x00000000,
	0x5478, 0x000000f0,
	0x547c, 0x20000000,
	0x5480, 0x00000005,
	0x5484, 0x02800000,
	0x5488, 0xe0000800,
	0x548c, 0x03fc0000,
	0x5490, 0x00000001,
	0x5494, 0x00000000,
	0x5498, 0x00000300,
	0x549c, 0x00500000,
	0x54a0, 0xc0000000,
	0x54a4, 0x00109200,
	0x54a8, 0x00000010,
	0x54ac, 0x00000000,
	0x54b0, 0x00f20006,
	0x54b4, 0x000000e9,
	0x54b8, 0x00000000,
	0x54bc, 0x00000000,
	0x54c0, 0x000ce000,
	0x54c4, 0x0007e0ab,
	0x54c8, 0x00024051,
	0x54cc, 0x00000012,
	0x54d0, 0x00000000,
	0x54d4, 0x1212100b,
	0x54d8, 0x00000006,
	0x54dc, 0x00000000,
	0x54e0, 0x00000872,
	0x54e4, 0x00000003,
	0x54e8, 0x000003d9,
	0x54ec, 0x00000000,
	0x54f0, 0x00000001,
	0x54f4, 0x25294992,
	0x54f8, 0x1ce62a52,
	0x54fc, 0x1cf739ce,
	0x5500, 0x5ce739ce,
	0x5504, 0x0002908e,
	0x5508, 0x00000001,
	0x550c, 0x00000037,
	0x5510, 0x000000a8,
	0x5514, 0x00000004,
	0x5698, 0xe02103fe,
	0x569c, 0xb20a7b28,
	0x56a0, 0xc6a7b14f,
	0x56a4, 0x0000003b,
	0x56a8, 0x009b902a,
	0x56ac, 0x009b902a,
	0x56b0, 0x98682c18,
	0x56b4, 0x6308c4c1,
	0x56b8, 0x6248c631,
	0x56bc, 0x922a8253,
	0x56c0, 0x00000005,
	0x56c4, 0x00001759,
	0x56c8, 0x4b802000,
	0x56cc, 0x831408be,
	0x56d0, 0x9898a8bb,
	0x56d4, 0x54535368,
	0x56d8, 0x999999b3,
	0x56dc, 0x35555589,
	0x56e0, 0x00000F45,
	0x56e4, 0x27039ce9,
	0x56e8, 0x31313432,
	0x56ec, 0x64658342,
	0x56f0, 0x00000005,
	0x56f4, 0x00000005,
	0x56f8, 0xc7013016,
	0x56fc, 0x84413016,
	0x5700, 0x84413016,
	0x5704, 0x8c413016,
	0x5708, 0x8c40b028,
	0x570c, 0x3140b028,
	0x5710, 0x2940b028,
	0x5714, 0x8440b028,
	0x5718, 0x2318c610,
	0x571c, 0x45334753,
	0x5720, 0x236a6a88,
	0x5724, 0x576df814,
	0x5728, 0xa08877ac,
	0x572c, 0x0000007a,
	0x5730, 0xbceb4a14,
	0x5734, 0x000a3a4a,
	0x5738, 0xbceb4a14,
	0x573c, 0x000a3a4a,
	0x5740, 0x9a8a8a97,
	0x5744, 0x0ca3b99a,
	0x5748, 0x38384242,
	0x574c, 0x0086402e,
	0x5750, 0x06e066aa,
	0x5754, 0x00008a62,
	0x5758, 0x00000008,
	0x575c, 0x009b902a,
	0x5760, 0x009b902a,
	0x5764, 0x98682c18,
	0x5768, 0x6308c4c1,
	0x576c, 0x6248c631,
	0x5770, 0x922a8253,
	0x5774, 0x00000005,
	0x5778, 0x00001759,
	0x577c, 0x4b802000,
	0x5780, 0x831408be,
	0x5784, 0x9898a8bb,
	0x5788, 0x54535368,
	0x578c, 0x999999b3,
	0x5790, 0x35555589,
	0x5794, 0x00000745,
	0x5798, 0x27039ce9,
	0x579c, 0x31313432,
	0x57a0, 0x64658342,
	0x57a4, 0x00000005,
	0x57a8, 0x00000005,
	0x57ac, 0xc7013016,
	0x57b0, 0x84413016,
	0x57b4, 0x84413016,
	0x57b8, 0x8c413016,
	0x57bc, 0x8c40b028,
	0x57c0, 0x3140b028,
	0x57c4, 0x2940b028,
	0x57c8, 0x8440b028,
	0x57cc, 0x2318c610,
	0x57d0, 0x45334753,
	0x57d4, 0x236a6a88,
	0x57d8, 0x576df814,
	0x57dc, 0xa08877ac,
	0x57e0, 0x0000007a,
	0x57e4, 0xbceb4a14,
	0x57e8, 0x000a3a4a,
	0x57ec, 0xbceb4a14,
	0x57f0, 0x000a3a4a,
	0x57f4, 0x9a8a8a97,
	0x57f8, 0x0ca3b99a,
	0x57fc, 0x38384242,
	0x5800, 0x0086402e,
	0x5804, 0x06e066aa,
	0x5808, 0x00008a62,
	0x580c, 0x00000008,
	0x5810, 0x80040000,
	0x5814, 0x80040000,
	0x5818, 0xfe800000,
	0x581c, 0x834c0000,
	0x5820, 0x00000000,
	0x5824, 0x00000000,
	0x5828, 0x00000000,
	0x582c, 0x00000000,
	0x5830, 0x00000000,
	0x5834, 0x00000000,
	0x5838, 0x00000000,
	0x583c, 0x00000000,
	0x5840, 0x00000000,
	0x5844, 0x00000000,
	0x5848, 0x00000000,
	0x584c, 0x04065800,
	0x5850, 0x12010080,
	0x5854, 0x0e1e3e05,
	0x5858, 0x0a163068,
	0x585c, 0x00206040,
	0x5860, 0x02020202,
	0x5864, 0x0fbf6020,
	0x5868, 0x011f7efc,
	0x586c, 0x0fbf3efd,
	0x5870, 0x0000007d,
	0x5878, 0x8008962d,
	0x587c, 0x00000102,
	0x5880, 0x00000000,
	0x5884, 0x00000000,
	0x5888, 0x00000000,
	0x588c, 0x00000000,
	0x5890, 0x00000000,
	0x5894, 0x00000000,
	0x5898, 0x00000000,
	0x589c, 0x00000000,
	0x58a0, 0x00000000,
	0x58a4, 0x00000000,
	0x0abc, 0xa840e1bf,
	0x0ac0, 0x00000000,
	0x0ac4, 0x00000007,
	0x0ac8, 0x410e4000,
	0x0ad4, 0x1001436e,
	0x0ad8, 0x41000000,
	0x08b0, 0x00000002,
	0x0ae0, 0x017ffff2,
	0x0ae4, 0x0010a130,
	0x0ae4, 0x0010a130,
	0x0ae8, 0x000000ff,
	0x0ae4, 0x0010a130,
	0x0ad4, 0x1001436e,
	0x0aec, 0x00000020,
	0x0888, 0x00000000,
	0x0aec, 0x00000020,
	0x0f84, 0x0043f01d,
	0x4640, 0x76582bf7,
	0x4644, 0x00104630,
	0x4648, 0x0000fffc,
	0x464c, 0x00000000,
	0x4650, 0x00000000,
	0x4654, 0x00000035,
	0x4658, 0x00000000,
	0x465c, 0x00000000,
	0x4660, 0x00000000,
	0x4664, 0x00000000,
	0x4670, 0x00000000,
	0x4690, 0x000003ff,
	0x4694, 0x00000000,
	0x4698, 0x0000003f,
	0x469c, 0x00000000,
	0x46a0, 0x00000000,
	0x46a4, 0x00000000,
	0x46a8, 0x00000000,
	0x46ac, 0x00000000,
	0x4600, 0x77777777,
	0x4604, 0x99999999,
	0x4608, 0x99999999,
	0x460c, 0x00000070,
	0x4610, 0x20110900,
	0x4510, 0x20110fff,
	0x467c, 0x001c0408,
	0x4684, 0x00000007,
	0x4618, 0x50009c00,
	0x4680, 0x00000100,
	0x0894, 0x0001004f,
	0x0884, 0x601e0100,
	0x0890, 0xef810000,
	0x0880, 0x00000030,
	0x0338, 0x00000001,
	0x7860, 0x0219A6AE,
	0x78b0, 0x0003F800,
	0x7888, 0x0400EA02,
	0x0B00, 0xf30ce31c,
	0x0B04, 0x0cef1f33,
	0x0B08, 0x0c0c0c0c,
	0x0B0C, 0x0c0c0c0c,
	0x0B10, 0x80016000,
	0x0B14, 0x0001e000,
	0x0B18, 0x20022002,
	0x0B1C, 0xe0008001,
	0x0B20, 0xe000e000,
	0x0B24, 0xe000e000,
	0x0B28, 0xe000e000,
	0x0B2C, 0xe000e000,
	0x4CBC, 0x10104041,
	0x4CC0, 0x14411111,
	0x4DBC, 0x10104041,
	0x4DC0, 0x14411111,
	0x20, 0x00000001,
	0x24, 0x00000014,
	0x28, 0x20200401,
};

RTW89_DECL_TABLE_PHY_COND(rtw8852a_bb, rtw89_phy_cfg_bb);

