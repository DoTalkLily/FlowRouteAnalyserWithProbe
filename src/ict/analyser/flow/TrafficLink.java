/*
 * Filename: TrafficLink.java
 * Copyright: ICT (c) 2013-5-27
 * Description: 
 * Author: Lily
 */
package ict.analyser.flow;

import java.util.HashMap;

/**
 * 链路上的流量分业务 ftp，telnet，http，total 和other
 * 
 * @author Lily
 * @version 1.0, 2013-5-27
 */
public class TrafficLink {
	private int linkId = 0;// 链路id
	private long ftp = 0; // ftp业务流量，对应端口号21
	private long http = 0;// http 业务流量，端口80
	private long total = 0;// 总流量
	private long other = 0;// 其他流量
	private long telnet = 0;// telnet业务流量，端口23

	public TrafficLink(int linkId) {
		this.linkId = linkId;
	}

	/**
	 * 重置变量
	 */
	public void resetValues() {
		this.ftp = 0;
		this.http = 0;
		this.other = 0;
		this.total = 0;
		this.telnet = 0;
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

	/**
	 * @return Returns the ftp.
	 */
	public long getFtp() {
		return ftp;
	}

	/**
	 * @param ftp
	 *            The ftp to set.
	 */
	public void addFtp(long ftp) {
		this.ftp += ftp;
	}

	/**
	 * @return Returns the http.
	 */
	public long getHttp() {
		return http;
	}

	/**
	 * @param http
	 *            The http to set.
	 */
	public void addHttp(long http) {
		this.http += http;
	}

	/**
	 * @return Returns the total.
	 */
	public long getTotal() {
		return total;
	}

	/**
	 * @param total
	 *            The total to set.
	 */
	public void addTotal(long total) {
		this.total += total;
	}

	/**
	 * @return Returns the other.
	 */
	public long getOther() {
		return other;
	}

	/**
	 * @param other
	 *            The other to set.
	 */
	public void addOther(long other) {
		this.other += other;
	}

	/**
	 * @return Returns the telnet.
	 */
	public long getTelnet() {
		return telnet;
	}

	/**
	 * @param telnet
	 *            The telnet to set.
	 */
	public void addTelnet(long telnet) {
		this.telnet += telnet;
	}

	/*
	 * 将同一条链路上的相应业务流量累加
	 */
	public void combineTraffic(TrafficLink link) {
		if (link == null) {
			return;
		}
		// 累加相应业务流量
		this.ftp += link.getFtp();
		this.http += link.getHttp();
		this.telnet += link.getTelnet();
		this.other += link.getOther();
		this.total += link.getTotal();

	}

	/*
	 * 根据端口号累加相应流量
	 */
	public void addTraffic(long bytes, int port) {
		if (bytes == 0 || port == 0) {
			return;
		}

		this.total += bytes;// 累加总流量

		switch (port) {
		case 21:
			this.ftp += bytes;
			break;
		case 23:
			this.telnet += bytes;
			break;
		case 80:
			this.http += bytes;
			break;
		default:
			this.other += bytes;
		}
	}

	public HashMap<String, Long> getProtocalBytes() {
		HashMap<String, Long> mapProtocalBytes = new HashMap<String, Long>();

		if (this.http != 0) {
			mapProtocalBytes.put("http", this.http);
		}
		if (this.telnet != 0) {
			mapProtocalBytes.put("telnet", this.telnet);
		}
		if (this.ftp != 0) {
			mapProtocalBytes.put("ftp", this.ftp);
		}
		if (this.other != 0) {
			mapProtocalBytes.put("other", this.other);
		}

		return mapProtocalBytes;
	}
}
