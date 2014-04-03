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
	private Path path = null;// 路径
	private Netflow netflow = null;// flow中包含的netflow对象

	public Flow(Netflow netflow, Path path) {
		this.path = path;
		this.netflow = netflow;
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
}
