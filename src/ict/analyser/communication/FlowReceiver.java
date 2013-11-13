/*
 * Filename: FlowReceiver.java
 * Copyright: ICT (c) 2012-10-25
 * Description: 每隔15分钟从内存中读取一批netflow报文并解析
 * Author: 25hours
 */
package ict.analyser.communication;

import ict.analyser.netflow.Netflow;
import ict.analyser.tools.Utils;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.TimerTask;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * 
 * @author 25hours
 * @version 1.0, 2012-10-25
 * @version 1.1, 2013-2-18 加出错重连接机制和数据传输中断处理机制
 */
public class FlowReceiver extends TimerTask {
	private Socket client = null;// 保存接收到连接的socket
	private byte[] allBytes = null;// 从硬件设备收到的全部bytes
	private static int INDEX = 0;// 将流量byte拷贝到单个byte数组的索引
	private static int COUNTER = 0;// 本周期流量条数
	private static int PORT = 1234; // 硬件设备发送流量的端口
	private static int TRY_COUNT = 1;// 如果连接失败，或者读数据失败，尝试重连接的次数
	private static int FLOW_SIZE = 64;// 一条流量的byte数组大小
	private static int WHOLE_BYTES = 0;// 接收到的全部流量byte和
	private static int ANALYSER_COUNT = 5;// 分析线程数量
	private static int TRY_INTERVAL = 3 * 1000;// 两次尝试重连的时间间隔，单位： 秒
	private static int BUFFER_SIZE = 10 * 1024 * 1024;// 接受文件缓存的最大大小
	private static boolean GET_WHOLE_BYTE = false;// 是否正在接收流量传输
	private static boolean PROCESS_FLOW_FINISHED = false;// 是否已将全部bytes解析成流量对象
	private static String IP = "localhost"; // 请求流量的地址
	private Lock lock = null;// 加锁
	private DataInputStream in = null;// 输入流
	private DataOutputStream out = null;// 输出流到本地文件
	private Condition condition = null;// 锁相关：设置等待唤醒，相当于wait/notify
	private ArrayList<Netflow> allFlows = null;// 本周期全部流量
	private Logger logger = Logger.getLogger(FlowReceiver.class.getName());// 注册一个logger

	public FlowReceiver() {
		this.lock = new ReentrantLock();
		this.condition = lock.newCondition();
		this.allFlows = new ArrayList<Netflow>();
	}

	@Override
	public void run() {
		doTask();// 初始化一个socket和输入输出流
	}

	private void doTask() {
		resetVariables();// 重置变量
		getFlow();// 得到流量报文
		processFlow();// 处理得到的字节
	}

	private void resetVariables() {
		INDEX = 0;
		COUNTER = 0;
		TRY_COUNT = 1;
		WHOLE_BYTES = 0;
		PROCESS_FLOW_FINISHED = false;

		allFlows.clear();
	}

	private void getFlow() {
		try {
			openBufferedConnect();// 建立带缓存连接
			sendOrder(3);// 发送流量请求
			getOrder(4);// 得到响应
		} catch (IOException e) {
			faultProcess(e);

			if (TRY_COUNT <= 3) {
				TRY_COUNT++;
				getFlow();
			} else {
				TRY_COUNT = 1;
				WHOLE_BYTES = 0;
				return;
			}
		}

		TRY_COUNT = 1;

		logger.info("whole_bytes:" + WHOLE_BYTES);

		if (WHOLE_BYTES == 0) {// 本周期没有流量
			logger.warning("getFlow failed！");
			return;
		}

		if (WHOLE_BYTES % FLOW_SIZE != 0) {
			logger.warning("WHOLE_BYTES cannot divided by FLOW_SIZE ! Flow data invalid!");
			return;
		}

		int read = 0;
		int passedlen = 0;// 记录传输长度i
		byte[] buf = new byte[BUFFER_SIZE];// 开辟一个接收文件缓冲区
		this.allBytes = new byte[WHOLE_BYTES + 10];// 开辟一段内存
		// 获取全部流量
		try {
			while (passedlen < WHOLE_BYTES) {
				read = this.in.read(buf);

				if (read == -1) {
					break;
				}

				System.arraycopy(buf, 0, this.allBytes, passedlen, read);
				passedlen += read;// 记录下一次要拷贝的起始点
				read = 0;
			}

			logger.info("流量接收了" + (passedlen * 100) / WHOLE_BYTES + "%");
		} catch (IOException e) {// 如果数据发送过程错误中断，抛弃本周期数据
			WHOLE_BYTES = 0;
			e.printStackTrace();
		} finally {
			TRY_COUNT = 1;
			closeConnect();
		}
	}

	public void processFlow() {
		if (WHOLE_BYTES == 0) {
			lock.lock();
			try {
				condition.signalAll();
			} finally {
				lock.unlock();
			}
			return;
		}

		logger.info("processFlow....");

		ArrayList<FlowProcesser> pros = new ArrayList<FlowProcesser>();
		FlowProcesser pro = null;

		for (int i = 0; i < ANALYSER_COUNT; i++) {
			pro = new FlowProcesser(this);
			pros.add(pro);
			pro.start();
			// 起5个线程开始分析，这里将来可以考虑用线程池
		}

		for (int i = 0; i < ANALYSER_COUNT; i++) {
			try {
				pros.get(i).join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

		lock.lock();
		try {
			PROCESS_FLOW_FINISHED = true;
			condition.signalAll();
		} finally {
			lock.unlock();
		}
	}

	public synchronized byte[] getOneFlowBytes() {
		byte[] oneFlow = new byte[FLOW_SIZE + 1];

		if ((INDEX + FLOW_SIZE) <= WHOLE_BYTES) {
			System.arraycopy(this.allBytes, INDEX, oneFlow, 0, FLOW_SIZE);
			INDEX += FLOW_SIZE;
			return oneFlow;
		}

		return null;
	}

	public synchronized void insertFlow(Netflow flow) {
		if (flow != null) {
			COUNTER++;
			this.allFlows.add(flow);
		}

	}

	public ArrayList<Netflow> getAllFlows(int pid) {
		lock.lock();
		try {
			if (!GET_WHOLE_BYTE) {// 如果当前正在接受流量
				logger.info("analyzing the order got,waiting for 'WHOLE_BYTE' to be set");
				condition.await();
			}
			// 如果分析返回指令中，WHOLE_BYTE已经得到，但是为0，返回空
			if (WHOLE_BYTES == 0) {
				return null;
			}

			if (WHOLE_BYTES != 0 && INDEX <= (WHOLE_BYTES - FLOW_SIZE)) {
				logger.info("waiting for processing flows");// 如果正在处理流量
				condition.await();
			}

			if (!PROCESS_FLOW_FINISHED) {
				logger.info("waiting for inserting flow");// 解析完流量 等待线程插入流量
				condition.await();
			}

			logger.info("total flow count: " + COUNTER);

			return this.allFlows;
		} catch (InterruptedException e) {
			e.printStackTrace();
			return null;
		} finally {
			lock.unlock();
			INDEX = 0;
			WHOLE_BYTES = 0;
			GET_WHOLE_BYTE = false;
			PROCESS_FLOW_FINISHED = false;
			allBytes = null;
		}
	}

	public boolean sendStartSignal() {

		try {
			openConnect();// 建立连接
			sendOrder(1);// 发送打开命令
			getOrder(2);// 得到应答指令
		} catch (IOException e) {
			faultProcess(e);

			if (TRY_COUNT <= 3) {
				TRY_COUNT++;
				sendStartSignal();
			} else {
				TRY_COUNT = 1;
			}
			return false;
		}
		closeConnect();// 关闭连接
		logger.info("starting the device successfully!");
		return true;
	}

	/**
	 * 关闭采集流量模块
	 * 
	 * @return 关闭成功与否
	 */
	public boolean sendCloseSignal() {
		try {
			openConnect();// 建立连接
			sendOrder(5);// 发送请求命令码
			getOrder(6);// 解析应答端的应答
		} catch (IOException e) {
			faultProcess(e);

			if (TRY_COUNT <= 3) {
				TRY_COUNT++;
				sendCloseSignal();
			} else {
				TRY_COUNT = 1;
				return false;
			}
		}

		closeConnect();// 关闭连接

		logger.info("closing the device successfully!");
		return true;
	}

	/**
	 * 初始化输入输出流和socket
	 * 
	 * @throws IOException
	 * @throws UnknownHostException
	 * 
	 */
	private void openConnect() throws IOException {
		this.client = new Socket(IP, PORT);
		this.out = new DataOutputStream(client.getOutputStream());
		this.in = new DataInputStream(this.client.getInputStream());
	}

	/**
	 * 初始化输入输出流和socket
	 * 
	 * @throws IOException
	 * @throws UnknownHostException
	 * 
	 */
	private void openBufferedConnect() throws IOException {
		this.client = new Socket(IP, PORT);
		this.in = new DataInputStream(new BufferedInputStream(
				this.client.getInputStream()));
		this.out = new DataOutputStream(this.client.getOutputStream());
	}

	/**
	 * 关闭输入输出流和socket
	 * 
	 */
	public void closeConnect() {
		try {
			if (this.in != null) {
				this.in.close();
			}

			if (this.out != null) {
				this.out.close();
			}

			if (client != null) {
				client.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void sendOrder(int orderCode) throws IOException {
		byte[] data = new byte[8];
		byte[] cmd = null;

		cmd = Utils.IntToByte2(orderCode);// 构造命令码
		System.arraycopy(cmd, 0, data, 0, 2);

		cmd = Utils.IntToByte2(0);// 构造应答状态值 2byte
		System.arraycopy(cmd, 0, data, 2, 2);

		cmd = Utils.IntToBytes4(0);// 构造数据长度值
		System.arraycopy(cmd, 0, data, 4, 4);

		this.out.write(data);
		this.out.flush();
	}

	public void getOrder(int orderCode) throws IOException {
		int read = 0;
		byte[] orderGot = new byte[8];

		read = this.in.read(orderGot);

		if (read < 8) {
			logger.warning("device not closed!");
			// +错误处理,这里错误处理都有待讨论……
		}

		int received = Utils.byte2int(orderGot, 0);// 得到应答命令码

		if (received != orderCode) {// 如果应答命令码不正常，报错
			// +错误处理
		}

		received = Utils.byte2int(orderGot, 2);// 应答状态

		if (received == 1) {// 应答失败

			received = Utils.Bytes4ToInt(orderGot, 4);// 数据长度
			// 数据值这里有待定义 根据错误类型报错！
			// value ...
		}

		if (orderCode == 4) {// 如果命令码是4，代表响应的是流量读取请求,得到流量总大小
			WHOLE_BYTES = Utils.Bytes4ToInt(orderGot, 4);// 数据总长度

			lock.lock();
			try {
				GET_WHOLE_BYTE = true;
				condition.signalAll();
			} finally {
				lock.unlock();
			}
		}
	}

	private void faultProcess(IOException e1) {
		logger.info(e1.toString());

		closeConnect();

		if (TRY_COUNT > 3) {
			return;
		}

		logger.info("reconnecting.... " + TRY_COUNT + " times ");

		try {
			Thread.sleep(TRY_INTERVAL);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	// 20130226加，MainProcesser中待使用
	public void clearFlows() {
		if (this.allFlows != null && this.allFlows.size() != 0) {
			this.allFlows.clear();
		}
	}

}
