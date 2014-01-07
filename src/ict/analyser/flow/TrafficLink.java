/*
 * Filename: TrafficLink.java
 * Copyright: ICT (c) 2013-5-27
 * Description: 
 * Author: Lily
 */
package ict.analyser.flow;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

/**
 * 链路上的流量分业务 ftp，telnet，http，total 和other
 * 
 * @author Lily
 * @version 1.0, 2013-5-27
 */
public class TrafficLink {
	private int linkId = 0;// 链路id
	private long totalBytes = 0;// 链路总流量
	private HashMap<String, Long> mapProtocalBytes;

	public TrafficLink(int linkId) {
		this.linkId = linkId;
	}

	/*
	 * 将同一条链路上的相应业务流量累加
	 */
	public void combineTraffic(TrafficLink link) {
		if (link == null) {
			return;
		}

		HashMap<String, Long> mapToAdd = link.getProtocalBytes();

		if (mapToAdd == null || mapToAdd.size() == 0) {
			return;
		}

		// 累加相应业务流量
		Long bytes;
		String protocal;
		Entry<String, Long> entry;
		Iterator<Entry<String, Long>> iterator = mapToAdd.entrySet().iterator();

		while (iterator.hasNext()) {
			entry = iterator.next();
			bytes = entry.getValue();
			protocal = entry.getKey();

			this.totalBytes += bytes;// 累加总流量
			this.mapProtocalBytes.put(protocal,
					this.mapProtocalBytes.get(protocal) + bytes);
		}
	}

	/*
	 * 根据端口号累加相应流量
	 */
	public void addTraffic(String protocal, long bytes) {
		if (protocal == null || bytes == 0) {
			return;
		}

		this.totalBytes += bytes;// 累加总流量
		this.mapProtocalBytes.put(protocal, this.mapProtocalBytes.get(protocal)
				+ bytes);// 累加相应协议流量
	}

	public HashMap<String, Long> getProtocalBytes() {
		return this.mapProtocalBytes;
	}

	public long getTotal() {
		return this.totalBytes;
	}

	/**
	 * @param mapProtocalBytes
	 *            The mapProtocalBytes to set.
	 */
	public void setMapProtocalBytes(HashMap<String, Long> mapProtocalBytes) {
		this.mapProtocalBytes = mapProtocalBytes;
	}

	/**
	 * 重置变量
	 */
	public void resetValues() {
		this.mapProtocalBytes.clear();
	}

	/**
	 * @return Returns the linkId.
	 */
	public int getLinkId() {
		return linkId;
	}

	/**
	 * @param linkId
	 *            The linkId to set.
	 */
	public void setLinkId(int linkId) {
		this.linkId = linkId;
	}

}
