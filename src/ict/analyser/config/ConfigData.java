/*
 * Filename: ConfigData.java
 * Copyright: Huawei Copyright (c) 2012-10-15
 * Description: 
 * Author: 25hours
 *
 * Modified by:
 * Modified time: 2012-10-15
 * Trace ID:
 * CR No:
 * Modified content:
 */
package ict.analyser.config;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-15
 */
public class ConfigData {

	private String globalAnalysisIP = null;// 综合分析接收结果的ip

	private int globalAnalysisPort = 0;// 综合分析接收结果的端口号

	private int interval = 15;// 周期

	private int topN = 10;// topN

	private int inAdvance = 20;

	private String protocol = "ospf";// 协议类型

	/**
	 * @return Returns the globalAnalysisIP.
	 */
	public String getGlobalAnalysisIP() {
		return globalAnalysisIP;
	}

	/**
	 * @param globalAnalysisIP
	 *            The globalAnalysisIP to set.
	 */
	public void setGlobalAnalysisIP(String globalAnalysisIP) {
		this.globalAnalysisIP = globalAnalysisIP;
	}

	/**
	 * @return Returns the globalAnalysisPort.
	 */
	public int getGlobalAnalysisPort() {
		return globalAnalysisPort;
	}

	/**
	 * @return Returns the inAdvance.
	 */
	public int getInAdvance() {
		return inAdvance;
	}

	/**
	 * @param inAdvance
	 *            The inAdvance to set.
	 */
	public void setInAdvance(int inAdvance) {
		this.inAdvance = inAdvance;
	}

	/**
	 * @param globalAnalysisPort
	 *            The globalAnalysisPort to set.
	 */
	public void setGlobalAnalysisPort(int globalAnalysisPort) {
		this.globalAnalysisPort = globalAnalysisPort;
	}

	/**
	 * @return Returns the interval.
	 */
	public int getInterval() {
		return interval;
	}

	/**
	 * @param interval
	 *            The interval to set.
	 */
	public void setInterval(int interval) {
		this.interval = interval;
	}

	/**
	 * @return Returns the topN.
	 */
	public int getTopN() {
		return topN;
	}

	/**
	 * @param topN
	 *            The topN to set.
	 */
	public void setTopN(int topN) {
		this.topN = topN;
	}

	/**
	 * @return Returns the protocol.
	 */
	public String getProtocol() {
		return protocol;
	}

	/**
	 * @param protocol
	 *            The protocol to set.
	 */
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

}
