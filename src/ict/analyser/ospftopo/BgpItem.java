/*
 * Filename: BgpItem.java
 * Copyright: ICT (c) 2013-9-6
 * Description: 
 * Author: Lily
 */
package ict.analyser.ospftopo;

import ict.analyser.tools.IPTranslator;

import java.util.ArrayList;

/**
 * 1.Prefer the path with the highest WEIGHT.
 * 
 * 2.Prefer the path with the highestLOCAL_PREF.
 * 
 * 3. Prefer the path that was locally originated via a network or aggregate BGP
 * subcommand or through redistribution from an IGP.nexthop=0.0.0.0 的
 * ，这里不考虑as内部路由
 * 
 * 4. Prefer the path with the shortest AS_PATH.
 * 
 * 5. Prefer the path with the lowest origin type.
 * 
 * 0 I 对于产生它的AS是内部的
 * 
 * 1 E 来自外部网关协议（EGP）
 * 
 * 2 ? 是通过其他方法学习到的，绝大多数 情况下，它是从其他某种协议重新发布的
 * 
 * 6. Prefer the path with the lowest multi-exit discriminator (MED).
 * 
 * @author Lily
 * @version 1.0, 2013-9-6
 */
public class BgpItem implements Cloneable {
	private int origin = 0;// origin属性
	private int weight = 0;// cisco 专用越大越优先
	private int length = 0;// mask中1的个数
	private long med = 0;// 可能会有 4,294,967,294. 越小越优先
	private long prefix = 0;// 宣告前缀
	private long nextHop = 0;// 下一跳地址
	private int localProference = 0;// 本地优先级属性
	private ArrayList<Integer> asPath = null;// as path属性

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
	public long getMed() {
		return med;
	}

	/**
	 * @param metric
	 *            The metric to set.
	 */
	public void setMetric(int metric) {
		this.med = metric;
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

	/**
	 * @return Returns the origin.
	 */
	public int getOrigin() {
		return origin;
	}

	/**
	 * @param origin
	 *            The origin to set.
	 */
	public void setOrigin(int origin) {
		this.origin = origin;
	}

	/**
	 * @return Returns the weight.
	 */
	public int getWeight() {
		return weight;
	}

	/**
	 * @param weight
	 *            The weight to set.
	 */
	public void setWeight(int weight) {
		this.weight = weight;
	}

	/**
	 * @param metric
	 *            The metric to set.
	 */
	public void setMetric(long metric) {
		this.med = metric;
	}

	public void printDetail() {
		System.out.println("origin:" + origin + "  weight:" + weight
				+ "  length:" + length + "  med:" + med + " prefix:"
				+ IPTranslator.calLongToIp(prefix) + "  nexthop:"
				+ IPTranslator.calLongToIp(nextHop) + " localpreference:"
				+ localProference + " aspath:" + asPath.toString());
	}
}
