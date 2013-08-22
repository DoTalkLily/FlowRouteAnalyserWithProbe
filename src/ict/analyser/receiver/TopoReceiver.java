/*
 * Filename: TopoReceiver.java
 * Copyright: ICT (c) 2012-10-25
 * Description: 是一个server，接收topo文件
 * Author: 25hours
 */
package ict.analyser.receiver;

import ict.analyser.analysis.MainProcesser;
import ict.analyser.config.ConfigData;
import ict.analyser.isistopo.IsisTopo;
import ict.analyser.ospftopo.OspfTopo;
import ict.analyser.tools.FileProcesser;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-25
 * @version 1.1, 2013-2-18 添加容错机制，如果一个连接错误或者数据传输错误，关闭连接，不解析拓扑
 */
public class TopoReceiver extends Thread {

	private static int port = 2012;// 端口号(待定)

	private static int bufferSize = 50 * 1024;// 缓冲区大小

	private boolean signal = false;// 第一个周期开始接收文件时发送给主线程的signal

	private Socket client = null;// 保存接收到连接的socket

	private Lock topoLocker = null;// 为topo数据加锁

	private Lock signalLocker = null;// 为信号加锁

	private String protocol = null;// 协议类型

	private IsisTopo isisTopo = null;// 保存解析得到的ospfTopo文件

	private OspfTopo ospfTopo = null;// 保存解析得到的ospfTopo文件

	private PrintWriter writer = null;// 输出流

	private ServerSocket server = null;// 服务器socket

	private ConfigData configData = null;// 保存解析后得到的配置信息的类，主分析进程将读取

	private DataInputStream fileIn = null;// 输入流

	private MainProcesser processer = null;// 主分析类

	private DataOutputStream fileOut = null;// 输出流到本地文件

	private Condition topoCondition = null;// 锁相关：设置等待唤醒，相当于wait/notify

	private Condition signalCondition = null;// 锁相关：设置等待唤醒，相当于wait/notify

	private String ospfPath = "ospf_topo.json";// 接收到的文件保存到的路径本地(待定)

	private String isisPath = "isis_topo.json";// 接收到的文件保存到的路径本地(待定)

	private FileProcesser fileProcesser = null;// 解析topo文件类

	// routerid——BGP表映射

	public TopoReceiver(MainProcesser processer) {
		// 初始化各类变量
		this.processer = processer;
		this.topoLocker = new ReentrantLock();
		this.signalLocker = new ReentrantLock();
		this.fileProcesser = new FileProcesser();
		this.topoCondition = topoLocker.newCondition();
		this.signalCondition = signalLocker.newCondition();

		try {
			server = new ServerSocket(port);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void run() {
		while (true) {
			doTask();
		}
	}

	/**
	 * 初始化一个socket和输入输出流
	 * 
	 */
	private void doTask() {
		try {
			initAConnect();

			getFile(); // 接收文件，写入本地文件，调用函数解析

		} catch (IOException e1) {
			e1.printStackTrace();
			return;
		} finally {
			closeTask();// 关闭输入输出流和socket
		}

		processTopo();// 调用FileProcesser的函数处理配置信息
	}

	private void initAConnect() throws IOException {
		this.client = server.accept();
		// if (MainProcesser.periodId == 1) {//
		// 第一个周期，在接收到socket连接时发送信号给MainProcesser，MainProcesser接收到信号后开启netflow报文接收模块
		if (this.client != null) {
			this.ospfTopo = null;
			this.isisTopo = null;
			sendSignal();
		} else {
			return;
		}
		// }
		this.configData = this.processer.getConfigData();
		this.protocol = this.configData.getProtocol();
		this.fileIn = new DataInputStream(new BufferedInputStream(
				this.client.getInputStream()));

		if (this.protocol.equalsIgnoreCase("ospf")) {
			this.fileOut = new DataOutputStream(new BufferedOutputStream(
					new BufferedOutputStream(
							new FileOutputStream(this.ospfPath))));
		} else {
			this.fileOut = new DataOutputStream(new BufferedOutputStream(
					new BufferedOutputStream(
							new FileOutputStream(this.isisPath))));
		}

		this.writer = new PrintWriter(this.client.getOutputStream(), true);
	}

	/**
	 * 接收文件，写入本地文件，调用函数解析
	 * 
	 * @throws IOException
	 * 
	 */
	private void getFile() throws IOException {
		// 缓冲区
		byte[] buf = new byte[bufferSize];// 开辟一个接收文件缓冲区
		int passedlen = 0;// 记录传输长度i

		// len = this.fileIn.readLong();// 获取文件长度
		// System.out.println("拓扑文件文件的长度为:" + len + "B");

		// if (len > 0) {// 如果接收到文件
		this.isisTopo = null;
		this.ospfTopo = null;
		// 获取文件
		while (true) {
			int read = 0;
			// if (this.fileIn != null) {
			read = this.fileIn.read(buf);
			// }
			passedlen += read;
			if (read == -1) {
				break;
			}
			this.fileOut.write(buf, 0, read);
		}
		System.out.println("拓扑文件接收了" + passedlen + "B");
		// }
		writer.println("ack");// 向服务器发送ack
	}

	/**
	 * 关闭输入输出流和socket
	 * 
	 */
	private void closeTask() {
		try {
			if (fileOut != null) {
				fileOut.close();
			}
			if (writer != null) {
				writer.close();
			}
			if (fileIn != null) {
				fileIn.close();
			}
			if (client != null) {
				client.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 调用FileProcesser的函数处理配置信息
	 * 
	 */
	private void processTopo() {
		topoLocker.lock();

		try {
			// 调用处理topo文件函数!!!!写在FileProcesser里
			// System.out.println("protocol:" + this.protocol);
			if (this.protocol.equalsIgnoreCase("ospf")) {
				this.ospfTopo = null;
				this.ospfTopo = fileProcesser.readOspfTopo(this.ospfPath);
				if (this.ospfTopo == null) {
					return;
				}
			} else {
				this.isisTopo = fileProcesser.readIsisTopo(this.isisPath);
				if (isisTopo == null) {
					return;
				}
			}

			topoCondition.signal();
		} finally {
			topoLocker.unlock();
		}

	}

	/**
	 * 返回ospf拓扑对象
	 * 
	 * @return ospf拓扑对象
	 */
	public OspfTopo getOspfTopo() {
		topoLocker.lock(); // 加锁
		try {
			if (this.ospfTopo == null) {// 如果没解析完成
				topoCondition.await();// 等待
			}
			return this.ospfTopo; // 返回一次拓扑后，拓扑设为空
		} catch (InterruptedException e) {
			e.printStackTrace();
			return null;
		} finally {
			topoLocker.unlock();// 解锁
		}
	}

	/**
	 * 返回ISIS拓扑对象
	 * 
	 * @return ospf拓扑对象
	 */
	public IsisTopo getIsisTopo() {
		topoLocker.lock(); // 加锁
		try {
			if (this.isisTopo == null) {// 如果没解析完成
				topoCondition.await();// 等待
			}

			return this.isisTopo;
		} catch (InterruptedException e) {
			e.printStackTrace();
			return null;
		} finally {
			topoLocker.unlock();// 解锁
		}
	}

	public void getTopoSignal() {
		signalLocker.lock();
		try {
			while (!signal) {
				signalCondition.await();
			}
			signal = false;
		} catch (InterruptedException e) {
			e.printStackTrace();
		} finally {
			signalLocker.unlock();
		}
	}

	public void sendSignal() {
		this.signalLocker.lock();
		try {
			this.signal = true;
			this.signalCondition.signal();
		} finally {
			this.signalLocker.unlock();
		}
	}
}
