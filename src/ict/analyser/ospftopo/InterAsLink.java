/*
 * Filename: InterAsFlows.java
 * Copyright: ICT (c) 2012-11-5
 * Description: 
 * Author: 25hours
 */
package ict.analyser.ospftopo;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-5
 */
public class InterAsLink {
	private long mask = 0;// 链路mask
	private int input = 0;// 接口索引
	private int metric = 0;// 链路上的metric值
	private int linkId = 0;// 标识链路的id
	private long myBrId = 0;// 本as的asbr的id
	private long myInterIp = 0;// 本ASBR设备接口ip
	private long neighborAS = 0;// 邻居as
	private long neighborBrIp = 0;// 邻居as的asbr的接口ip
	private long neighborBrId = 0;// 邻居as的asbr 的接口id

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
	 * @return Returns the myBrId.
	 */
	public long getMyBrId() {
		return myBrId;
	}

	/**
	 * @param myBrId
	 *            The myBrId to set.
	 */
	public void setMyBrId(long myBrId) {
		this.myBrId = myBrId;
	}

	/**
	 * @return Returns the myInterIp.
	 */
	public long getMyInterIp() {
		return myInterIp;
	}

	/**
	 * @param myInterIp
	 *            The myInterIp to set.
	 */
	public void setMyInterIp(long myInterIp) {
		this.myInterIp = myInterIp;
	}

	/**
	 * @return Returns the mask.
	 */
	public long getMask() {
		return mask;
	}

	/**
	 * @param mask
	 *            The mask to set.
	 */
	public void setMask(long mask) {
		this.mask = mask;
	}

	/**
	 * @return Returns the neighborBrId.
	 */
	public long getNeighborBrId() {
		return neighborBrId;
	}

	/**
	 * @param neighborBrId
	 *            The neighborBrId to set.
	 */
	public void setNeighborBrId(long neighborBrId) {
		this.neighborBrId = neighborBrId;
	}

	/**
	 * @return Returns the neighborAS.
	 */
	public long getNeighborAS() {
		return neighborAS;
	}

	/**
	 * @param neighborAS
	 *            The neighborAS to set.
	 */
	public void setNeighborAS(long neighborAS) {
		this.neighborAS = neighborAS;
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
	 * @return Returns the input.
	 */
	public int getInput() {
		return input;
	}

	/**
	 * @param input
	 *            The input to set.
	 */
	public void setInput(int input) {
		this.input = input;
	}

	/**
	 * @return Returns the neighborBrIp.
	 */
	public long getNeighborBrIp() {
		return neighborBrIp;
	}

	/**
	 * @param neighborBrIp
	 *            The neighborBrIp to set.
	 */
	public void setNeighborBrIp(long neighborBrIp) {
		this.neighborBrIp = neighborBrIp;
	}

	public long getPrefix() {
		return this.myInterIp & this.mask;
	}
}
