/*
 * Filename: AsExternalLSA.java
 * Copyright: Huawei Copyright (c) 2012-10-18
 * Description: 
 * Author: 25hours
 *
 * Modified by:
 * Modified time: 2012-10-18
 * Trace ID:
 * CR No:
 * Modified content:
 */
package ict.analyser.ospftopo;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-18
 */
public class AsExternalLSA implements Cloneable {
	private int metric = 0;
	private long advRouter = 0;
	private long linkStateId = 0;
	private long networkMask = 0;
	private int externalType = 0;
	private long forwardingAddress = 0;

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
	 * @return Returns the advRouter.
	 */
	public long getAdvRouter() {
		return advRouter;
	}

	/**
	 * @param advRouter
	 *            The advRouter to set.
	 */
	public void setAdvRouter(long advRouter) {
		this.advRouter = advRouter;
	}

	/**
	 * @return Returns the linkStateId.
	 */
	public long getLinkStateId() {
		return linkStateId;
	}

	/**
	 * @param linkStateId
	 *            The linkStateId to set.
	 */
	public void setLinkStateId(long linkStateId) {
		this.linkStateId = linkStateId;
	}

	/**
	 * @return Returns the networkMask.
	 */
	public long getNetworkMask() {
		return networkMask;
	}

	/**
	 * @param networkMask
	 *            The networkMask to set.
	 */
	public void setNetworkMask(long networkMask) {
		this.networkMask = networkMask;
	}

	/**
	 * @return Returns the externalType.
	 */
	public int getExternalType() {
		return externalType;
	}

	/**
	 * @param externalType
	 *            The externalType to set.
	 */
	public void setExternalType(int externalType) {
		this.externalType = externalType;
	}

	/**
	 * @return Returns the forwardingAddress.
	 */
	public long getForwardingAddress() {
		return forwardingAddress;
	}

	/**
	 * @param forwardingAddress
	 *            The forwardingAddress to set.
	 */
	public void setForwardingAddress(long forwardingAddress) {
		this.forwardingAddress = forwardingAddress;
	}

}
