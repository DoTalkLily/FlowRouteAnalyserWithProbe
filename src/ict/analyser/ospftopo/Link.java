/*
 * Filename: Link.java
 * Copyright: ICT (c) 2012-10-18
 * Description: 
 * Author: 25hours
 */
package ict.analyser.ospftopo;

/**
 * 这种存储方式非常占内存！
 * 
 * @author 25hours
 * @version 1.0, 2012-10-18
 */
public class Link {
	private long myId = 0;// 本设备id
	private long mask = 0;
	private int linkId = 0;// 标识链路的id
	private int metric = 0;// 链路上的 cost值
	private String area = null;// 本链路所属area，也可理解为本接口所属area
	private long neighborId = 0;// 邻居设备id
	private long myInterIp = 0;// 本设备接口ip

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
	 * @return Returns the area.
	 */
	public String getArea() {
		return area;
	}

	/**
	 * @return prefix
	 */
	public long getPrefix() {
		return this.myInterIp & this.mask;
	}

	/**
	 * @param area
	 *            The area to set.
	 */
	public void setArea(String area) {
		this.area = area;
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
	 * @return Returns the myId.
	 */
	public long getMyId() {
		return myId;
	}

	/**
	 * @param myId
	 *            The myId to set.
	 */
	public void setMyId(long myId) {
		this.myId = myId;
	}

	/**
	 * @return Returns the neighborId.
	 */
	public long getNeighborId() {
		return neighborId;
	}

	/**
	 * @param neighborId
	 *            The neighborId to set.
	 */
	public void setNeighborId(long neighborId) {
		this.neighborId = neighborId;
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
}
