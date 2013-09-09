/*
 * Filename: BgpItem.java
 * Copyright: ICT (c) 2013-9-6
 * Description: 
 * Author: Lily
 */
package ict.analyser.ospftopo;

import java.util.ArrayList;

/**
 * 
 * "prefix": "10.21.3.0", "length": 23, "nexthop": "23.1.3.23",
 * "localPreference": 10, "metric": 100, "aspath": [ 12, 23, 44 ]
 * 
 * @author Lily
 * @version 1.0, 2013-9-6
 */
public class BgpItem {
	private int length = 0;
	private int metric = 0;
	private long prefix = 0;
	private long nextHop = 0;
	private int localProference = 0;
	private ArrayList<Integer> asPath = null;

	/**
	 * @return Returns the length.
	 */
	public int getLength() {
		return length;
	}

	/**
	 * @param length
	 *            The length to set.
	 */
	public void setLength(int length) {
		this.length = length;
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
	 * @return Returns the nextHop.
	 */
	public long getNextHop() {
		return nextHop;
	}

	/**
	 * @param nextHop
	 *            The nextHop to set.
	 */
	public void setNextHop(long nextHop) {
		this.nextHop = nextHop;
	}

	/**
	 * @return Returns the asPath.
	 */
	public ArrayList<Integer> getAsPath() {
		return asPath;
	}

	/**
	 * @param asPath
	 *            The asPath to set.
	 */
	public void setAsPath(ArrayList<Integer> asPath) {
		this.asPath = asPath;
	}

	/**
	 * @return Returns the localProference.
	 */
	public int getLocalProference() {
		return localProference;
	}

	/**
	 * @param localProference
	 *            The localProference to set.
	 */
	public void setLocalProference(int localProference) {
		this.localProference = localProference;
	}

}
