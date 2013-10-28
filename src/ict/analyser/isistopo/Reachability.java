/*
 * Filename: Reachability.java
 * Copyright: ICT (c) 2012-11-24
 * Description: 
 * Author: 25hours
 */
package ict.analyser.isistopo;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-24
 */
public class Reachability {
	private long sysId = 0;
	private long prefix = 0;
	private int metric = 0;

	/**
	 * @return Returns the sysId.
	 */
	public long getSysId() {
		return sysId;
	}

	/**
	 * @param sysId
	 *            The sysId to set.
	 */
	public void setSysId(long sysId) {
		this.sysId = sysId;
	}

	/**
	 * @return Returns the prefix.
	 */
	public long getPrefix() {
		return prefix;
	}

	/**
	 * @param prefix
	 *            The prefix to set.
	 */
	public void setPrefix(long prefix) {
		this.prefix = prefix;
	}

	/**
	 * @return Returns the metric.
	 */
	public int getMetric() {
		return metric;
	}

	/**
	 * @param metric
	 *            The metric to set.
	 */
	public void setMetric(int metric) {
		this.metric = metric;
	}
}
