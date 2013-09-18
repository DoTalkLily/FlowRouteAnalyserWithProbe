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
import ict.analyser.ospftopo.AsExternalLSA;
import ict.analyser.ospftopo.BgpItem;
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
import java.util.HashMap;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

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
	private boolean isTopoChanged = true;// 判断拓扑是否发生改变
	private boolean isOuterInfoChanged = true;// 判断bgp是否发生改变
	private Socket client = null;// 保存接收到连接的socket
	private Lock topoLocker = null;// 为topo数据加锁
	private String protocol = null;// 协议类型
	private Lock signalLocker = null;// 为信号加锁
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
	private Logger logger = Logger.getLogger(TopoReceiver.class.getName());// 注册一个logger

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
			initAConnect();// 初始化一个连接
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

		if (this.client != null) {// 如果接收到连接，说明可以开始下一个周期的分析，更改本地接受到拓扑文件的信号
			sendSignal();
		} else {
			return;
		}

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
		// 获取文件
		int read = 0;

		while (true) {
			read = this.fileIn.read(buf);
			passedlen += read;

			if (read == -1) {
				break;
			}

			this.fileOut.write(buf, 0, read);
		}

		logger.info("拓扑文件接收了" + passedlen + "B");
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
		this.isOuterInfoChanged = true;
		this.isTopoChanged = true;

		try {
			// 调用处理topo文件函数 写在FileProcesser里
			if (this.protocol.equalsIgnoreCase("ospf")) {
				OspfTopo newTopo = fileProcesser.readOspfTopo(this.ospfPath);
				this.isTopoChanged = fileProcesser.isTopoChanged();
				this.isOuterInfoChanged = fileProcesser.isOuterInfoChanged();

				if (fileProcesser.isTopoChanged()) {// 如果topo改变了
					if (fileProcesser.isOuterInfoChanged()) {// 如果bgp和LSA5信息变了
						if (newTopo == null) {// 但是没解析到拓扑数据，报错返回，用原来拓扑数据
							logError("topo is changed but no topo data!");
							return;
						}
						this.ospfTopo = newTopo;// 否则用新拓扑中数据
					} else { // 如果可达性信息没变
						if (newTopo == null) {// 新拓扑为空报错
							logError("topo is changed but no topo data!");
							return;
						}
						// 否则bgp用原来数据，但是用的是深拷贝，不然这种引用会导致原来的ospfTopo对象不能释放，导致内存泄露，拓扑部分用新数据
						HashMap<Long, BgpItem> mapPrefixBgp = this.ospfTopo
								.getMapPrefixBgpItem();
						HashMap<Long, AsExternalLSA> mapPrefixLsa5 = this.ospfTopo
								.getMapPrefixExternalLsa();
						this.ospfTopo = newTopo;
						this.ospfTopo.setMapPrefixBgpItem(mapPrefixBgp);
						this.ospfTopo.setMapPrefixExternalLsa(mapPrefixLsa5);
					}

				} else {// 如果拓扑没改变，只更改pid和外部信息
					long pid = fileProcesser.getPid();

					if (pid == 0) {
						logError("topo is not changed but pid is 0");
						return;
					}

					this.ospfTopo.setPeriodId(pid);

					if (fileProcesser.isOuterInfoChanged()) {// 如果拓扑没变，外部可达性信息改变了
						if (newTopo == null) {
							logError("topo is changed but no topo data!");
							return;
						}

						// 如果拓扑信息没变，只把bgp和external lsa信息更新，深拷贝，然后释放newTopo对象
						this.ospfTopo.setMapPrefixBgpItem(newTopo
								.getMapPrefixBgpItem());// 拓扑没变 bgp内容变了，只更新bgp数据
						this.ospfTopo.setMapPrefixExternalLsa(newTopo
								.getMapPrefixExternalLsa());
						newTopo = null;
					}
				}
			} else {// 处理isis情况，只需考虑拓扑
				IsisTopo newTopo = fileProcesser.readIsisTopo(this.isisPath);

				if (fileProcesser.isTopoChanged()) {// 如果topo改变了
					if (newTopo == null) {
						logError("topo is changed but no topo data!");
						return;
					}

					this.isisTopo = newTopo;
				} else {// 如果拓扑没改变，只更改pid
					long pid = fileProcesser.getPid();

					if (pid == 0) {
						logError("topo is not changed but pid is 0");
						return;
					}

					this.isisTopo.setPeriodId(pid);
				}
			}

			topoCondition.signal();// topo is ready
		} finally {
			topoLocker.unlock();
		}
	}

	private void logError(String msg) {
		this.isTopoChanged = false;
		this.isOuterInfoChanged = false;
		logger.warning(msg);
	}

	/**
	 * 返回ospf拓扑对象
	 * 
	 * @return ospf拓扑对象
	 */
	public OspfTopo getOspfTopo() {
		topoLocker.lock(); // 加锁
		try {
			topoCondition.await();// 等待
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
			topoCondition.await();// 等待
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
			if (!signal) {
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

	/**
	 * @return Returns the isTopoChanged.
	 */
	public boolean isTopoChanged() {
		return isTopoChanged;
	}

	/**
	 * @return Returns the isBgpChanged.
	 */
	public boolean isBgpChanged() {
		return isOuterInfoChanged;
	}
}
