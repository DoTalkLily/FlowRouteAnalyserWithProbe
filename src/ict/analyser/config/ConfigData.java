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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

/**
 * 
 * @author 25hours
 * @version 1.0, 2012-10-15
 */
public class ConfigData {
	private int topN = 10;// topN
	private int interval = 15;// 周期
	private int inAdvance = 20;// 提前分析路径时间
	private String protocol = "ospf";// 协议类型
	private int globalAnalysisPort = 0;// 综合分析接收结果的端口号
	private String globalAnalysisIP = null;// 综合分析接收结果的ip
	public static int SAMPLE_RATE = 1;// 采样比
	private static HashMap<Integer, String> mapPortProtocal = null;// 端口号——协议名映射，虽然这种存储方式可能多存重复协议名字，但是方便端口号查协议名的查找，这里元素数量非常少

	/**
	 * @return Returns the mapPortProtocal.
	 */
	public HashMap<Integer, String> getMapPortProtocal() {
		return mapPortProtocal;
	}

	/**
	 * @param mapPortProtocal
	 *            The mapPortProtocal to set.
	 */
	public void setMapPortProtocal(HashMap<Integer, String> map) {
		mapPortProtocal = map;
	}

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

	/**
	 * @return Returns the samplingRate.
	 */
	public int getSamplingRate() {
		return SAMPLE_RATE;
	}

	/**
	 * @param samplingRate
	 *            The samplingRate to set.
	 */
	public void setSamplingRate(int samplingRate) {
		SAMPLE_RATE = samplingRate;
	}

	// for test
	public void printDetail() {
		if (mapPortProtocal == null) {
			System.out.println("no config data!");
			return;
		}

		System.out.println("topN:" + this.topN + " interval:" + this.interval
				+ " inAdvance:" + this.inAdvance + "  samplingRate:"
				+ SAMPLE_RATE + " globalAnalysisIp:" + this.globalAnalysisIP
				+ " globalAnalysisPort:" + this.globalAnalysisPort
				+ " protocal:" + this.protocol);

		Entry<Integer, String> entry;
		Iterator<Entry<Integer, String>> iterator = mapPortProtocal.entrySet()
				.iterator();

		while (iterator.hasNext()) {
			entry = iterator.next();
			System.out.println("port:" + entry.getKey() + " protocal:"
					+ entry.getValue());
		}
	}

	public static String getProtocalByPort(int port) {
		if (port < 0) {
			System.out
					.println("params is wrong in ConfigData:getProtocalByPort "
							+ port);
			return null;
		}

		if (mapPortProtocal == null || mapPortProtocal.size() == 0) {// 在比较极端的情况，比如配置文件中端口———协议名为空字段时启用原始判断
			switch (port) {
			case 21:
				return "ftp";
			case 23:
				return "telnet";
			case 80:
				return "http";
			default:
				return "other";
			}
		}

		if (mapPortProtocal.containsKey(port)) {
			return mapPortProtocal.get(port);
		}

		return "other";
	}

	public static ArrayList<Integer> getPortStrByProtocal(String protocal) {
		if (protocal == null) {
			return null;
		}

		if (mapPortProtocal == null || mapPortProtocal.size() == 0) {
			return null;
		}

		boolean isOther = "other".equals(protocal) ? true : false;

		Entry<Integer, String> entry = null;
		ArrayList<Integer> ports = new ArrayList<Integer>();
		Iterator<Entry<Integer, String>> iterator = mapPortProtocal.entrySet()
				.iterator();

		while (iterator.hasNext()) {
			entry = iterator.next();
			if (isOther) {
				ports.add(entry.getKey());
			} else if (protocal.equals(entry.getValue())) {
				ports.add(entry.getKey());
			}
		}
		return ports;
	}

}
