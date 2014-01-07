/*
 * Filename: FlowProcesser.java
 * Copyright: ICT (c) 2012-12-11
 * Description: 
 * Author: 25hours
 */
package ict.analyser.communication;

import ict.analyser.netflow.Netflow;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-12-11
 */
public class FlowProcesser implements Runnable {

	private FlowReceiver collector = null;
	private Netflow currentFlow = null;

	public FlowProcesser(FlowReceiver collector) {
		this.collector = collector;
	}

	@Override
	public void run() {
		read_loop();
	}

	public void read_loop() {

		byte[] oneFlow = null;

		while (true) {
			oneFlow = this.collector.getOneFlowBytes();

			if (oneFlow == null) {
				break;
			}

			currentFlow = new Netflow(oneFlow);// 得到一条flow对象

			if (currentFlow != null) {
				this.collector.insertFlow(currentFlow);
			}
		}
	}
}
