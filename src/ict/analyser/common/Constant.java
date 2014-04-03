/*
 * Filename: Constant.java
 * Copyright: ICT (c) 2013-8-26
 * Description: 
 * Author: Lily
 */
package ict.analyser.common;

/**
 * 定义全局用到的静态变量
 * 
 * @author Lily
 * @version 1.0, 2013-8-26
 */
public class Constant {
	// 流量分析结果
	public final static int FLOW_ANALYSIS_SUCCESS = 0;
	public final static int DEVICE_DOWN = 1;
	public final static int TOPO_NOT_RECEIVED = 2;
	public final static int FLOW_NOT_RECEIVED = 3;
	public final static int CONFIG_NOT_RECEIVED = 4;
	// 流量类型
	public final static int INTERNAL_FLOW = 1;
	public final static int INBOUND_FLOW = 2;
	public final static int OUTBOUND_FLOW = 3;
	public final static int TRANSIT_FLOW = 4;
	// 流量地址
	public final static boolean SRC_ADDRESS = true;
	public final static boolean DST_ADDRESS = false;
	// 流量大小
	public final static int A_FEW = 10000;
	// 指令
	public final static boolean PRE_CAL = true;
	public final static boolean ROUTE_CAL = false;
	// 提前分析路径的线程数量和流量路径分析线程的数量
	public final static int PRECAL_THREAD_COUNT = 5;
	public final static int FLOWCAL_THREAD_COUNT = 5;
	// is-is网络类型
	public final static boolean LEVEL2 = true;
	public final static boolean LEVEL1 = false;
	// is-is索引类型
	public final static int IN_STUB = 1;
	public final static int FOUND_IN_REACH = 2;
	public final static int NOT_IN_REACH = 3;
	// 分区开始时间
	public final static int START_YEAR = 2014;
	// 数据库语句
	public final static String CREATE_TABLE = " (`pid` bigint(12)unsigned NOT NULL,`srcIP` bigint(12) unsigned NOT NULL,`dstIP` bigint(12) unsigned NOT NULL, `srcMask` smallint(5) NOT NULL,`dstMask` smallint(5) NOT NULL,`srcRouter` bigint(12) unsigned NOT NULL,`dstRouter` bigint(12) unsigned NOT NULL,`srcPort` smallint(5) unsigned NOT NULL,`dstPort` smallint(5) unsigned NOT NULL,`bytes` bigint(12) unsigned NOT NULL,`srcAS` smallint(5) unsigned NOT NULL,`dstAS` smallint(5) unsigned NOT NULL,`srcPrefix` bigint(12) unsigned NOT NULL,`dstPrefix` bigint(12) unsigned NOT NULL,`input` smallint(5) unsigned NOT NULL,`output` smallint(5) unsigned NOT NULL,`tos` smallint(5) unsigned NOT NULL,`path` mediumtext CHARACTER SET gb2312 NOT NULL,`startTime` int(10) unsigned NOT NULL,`endTime` int(10) unsigned NOT NULL,`protocal` smallint(5) unsigned NOT NULL,`routerIp` bigint(12) NOT NULL,`hour` int(5) NOT NULL,KEY `pIndex` (`pid`) USING BTREE,KEY `srcAddr` (`srcIP`) USING BTREE,KEY `dstAddr` (`dstIP`) USING BTREE) ENGINE=InnoDB DEFAULT CHARSET=latin1 PARTITION BY HASH(hour) PARTITIONS 24;";
}
