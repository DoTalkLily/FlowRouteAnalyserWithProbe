/*
 * Filename: Flow.java
 * Copyright: ICT (c) 2012-10-23
 * Description: 
 * Author: 25hours
 */
package ict.analyser.flow;

import ict.analyser.netflow.Netflow;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-23
 */
public class Flow {

	private long pid = 0;// 计算周期

	private Path path = null;// 路径

	private int direction = 0;

	public final static int internal = 1;

	public final static int inbound = 2;

	public final static int outbound = 3;

	public final static int transit = 4;

	private Netflow netflow = null;// flow中包含的netflow对象

	public Flow(long pid, Netflow netflow, Path path, int direction) {
		this.pid = pid;
		this.path = path;
		this.netflow = netflow;
		this.direction = direction;
	}

	// 临时加
	public Flow(Netflow netflow) {
		this.netflow = netflow;
	}

	/**
	 * @return Returns the netflow.
	 */
	public Netflow getNetflow() {
		return netflow;
	}

	/**
	 * @return Returns the direction.
	 */
	public int getDirection() {
		return direction;
	}

	/**
	 * @param direction
	 *            The direction to set.
	 */
	public void setDirection(int direction) {
		this.direction = direction;
	}

	/**
	 * @return Returns the path.
	 */
	public Path getPath() {
		return path;
	}

	public boolean compareTo(Flow flow) {
		long myBytes = this.netflow.getdOctets();
		long toCompare = flow.getNetflow().getdOctets();

		if (myBytes > toCompare) {
			return true;
		}

		return false;
	}

	/**
	 * @return Returns the pid.
	 */
	public long getPid() {
		return pid;
	}

	/**
	 * @param pid
	 *            The pid to set.
	 */
	public void setPid(long pid) {
		this.pid = pid;
	}
}
