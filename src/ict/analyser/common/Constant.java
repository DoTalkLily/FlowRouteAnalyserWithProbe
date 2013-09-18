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
	public final static int FLOW_ANALYSIS_SUCCESS = 0;
	public final static int DEVICE_DOWN = 1;
	public final static int TOPO_NOT_RECEIVED = 2;
	public final static int FLOW_NOT_RECEIVED = 3;
	public final static int CONFIG_NOT_RECEIVED = 4;
	// 流量类型
	public final static int INTERNAL_FLOW = 0;
	public final static int INBOUND_FLOW = 1;
	public final static int OUTBOUND_FLOW = 2;
	public final static int TRANSIT_FLOW = 3;

}
