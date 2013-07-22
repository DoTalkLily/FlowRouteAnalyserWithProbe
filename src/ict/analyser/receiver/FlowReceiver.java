/*
 * Filename: FlowReceiver.java
 * Copyright: ICT (c) 2012-10-25
 * Description: 每隔15分钟从内存中读取一批netflow报文并解析
 * Author: 25hours
 */
package ict.analyser.receiver;

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

/**
 * 
 * @author 25hours
 * @version 1.0, 2012-10-25
 * @version 1.1, 2013-2-18 加出错重连接机制和数据传输中断处理机制
 */
public class FlowReceiver extends TimerTask {

	private byte[] allBytes = null;

	private static int INDEX = 0;

	private static int FLOW_SIZE = 64;

	private static int WHOLE_BYTES = 0;

	private static int ANALYSER_COUNT = 5;

	private static int BUFFER_SIZE = 10 * 1024 * 1024;

	private static int tryCount = 1;// 如果连接失败，或者读数据失败，尝试重连接的次数

	private static int tryInterval = 3 * 1000;// 两次尝试重连的时间间隔，单位： 秒

	private static int port = 1234; // web发布与数据库板卡负责分发配置文件的端口\

	private static String ip = "localhost"; // web发布与数据库板卡负责分发配置文件的ip地址（暂定自己）

	private Socket client = null;// 保存接收到连接的socket

	private DataInputStream in = null;// 输入流

	private DataOutputStream out = null;// 输出流到本地文件

	private Lock lock = new ReentrantLock();// 加锁

	private Condition condition = lock.newCondition();// 锁相关：设置等待唤醒，相当于wait/notify

	private ArrayList<Netflow> allFlows = new ArrayList<Netflow>();

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
		counter = 0;
		INDEX = 0;
		processFlowFinished = false;
		tryCount = 1;
		WHOLE_BYTES = 0;
		allFlows.clear();
	}

	private void getFlow() {

		try {
			openBufferedConnect();// 建立带缓存连接
			sendOrder(3);// 发送流量请求
			getOrder(4);// 得到响应
		} catch (IOException e) {
			faultProcess(e);

			if (tryCount <= 3) {
				tryCount++;
				getFlow();
			} else {
				tryCount = 1;
				WHOLE_BYTES = 0;
				return;
			}
		}

		tryCount = 1;

		System.out.println("whole_bytes:" + WHOLE_BYTES);

		if (WHOLE_BYTES == 0) {// 本周期没有流量
			System.out.println("getFlow failed！");
			// out.writeByte(-1);// 这里还需要吗？？？
			// out.flush();
			return;
		}
		
		if(WHOLE_BYTES % FLOW_SIZE != 0){
			System.out.println("WHOLE_BYTES cannot divided by FLOW_SIZE ! Flow data invalid!");
			return;
		}

		this.allBytes = new byte[WHOLE_BYTES + 10];// 开辟一段内存
		byte[] buf = new byte[BUFFER_SIZE];// 开辟一个接收文件缓冲区
		int passedlen = 0;// 记录传输长度i
		int read = 0;
		// 获取全部流量
		try {

			while (passedlen < WHOLE_BYTES) {
				read = this.in.read(buf);

				if (read == -1) {
					break;
				}

				System.arraycopy(buf, 0, this.allBytes, passedlen, read);
				passedlen += read;// 记录下一次要拷贝的起始点
				// System.out.println("passlen:" + passedlen);
				read = 0;
			}

			System.out.println("流量接收了" + (passedlen * 100) / WHOLE_BYTES + "%");
			// writer.println("ack");// 向服务器发送ack
			// out.writeByte(-1);
			// out.flush();

		} catch (IOException e) {// 如果数据发送过程错误中断，抛弃本周期数据
			WHOLE_BYTES = 0;
			e.printStackTrace();
		} finally {

			tryCount = 1;
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

		System.out.println("processFlow....");

		ArrayList<FlowProcesser> pros = new ArrayList<FlowProcesser>();
		FlowProcesser pro = null;

		for (int i = 0; i < ANALYSER_COUNT; i++) {
			pro = new FlowProcesser(this);
			pros.add(pro);
			pro.start();
			// new Thread(new FlowProcesser(this)).start();//
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
			processFlowFinished = true;
			condition.signalAll();
		} finally {
			lock.unlock();
		}
	}

	boolean get_WHOLE_BYTE = false;
	boolean processFlowFinished = false;

	public synchronized byte[] getOneFlowBytes() {

		byte[] oneFlow = new byte[FLOW_SIZE + 1];

		if ((INDEX + FLOW_SIZE) <= WHOLE_BYTES) {

			System.arraycopy(this.allBytes, INDEX, oneFlow, 0, FLOW_SIZE);
			INDEX += FLOW_SIZE;

			return oneFlow;
		}

		return null;
	}

	static int counter = 0;

	public synchronized void insertFlow(Netflow flow) {
		if (flow != null) {
			// System.out.println("one flow inserted! ");
			// flow.getDetail();
			counter++;
			this.allFlows.add(flow);
		}

	}

	public ArrayList<Netflow> getAllFlows(int pid) {

		System.out.println("getAllFlows....");

		lock.lock();
		try {

			if (!get_WHOLE_BYTE) {
				System.out
						.println("analyzing the order got,waiting for 'WHOLE_BYTE' to be set");
				condition.await();
			}
			// 如果分析返回指令中，WHOLE_BYTE已经得到，但是为0，返回空
			if (WHOLE_BYTES == 0) {
				return null;
			}

			if (WHOLE_BYTES != 0 && INDEX <= (WHOLE_BYTES - FLOW_SIZE)) {
				System.out.println("waiting for processing flows");
				condition.await();
			}

			if (!processFlowFinished) {
				System.out.println("waiting for inserting flow");
				condition.await();
			}

			System.out.println("total flow count: " + counter);

			return this.allFlows;
		} catch (InterruptedException e) {
			e.printStackTrace();
			return null;
		} finally {
			lock.unlock();
			INDEX = 0;
			WHOLE_BYTES = 0;
			get_WHOLE_BYTE = false;
			processFlowFinished = false;
			// syn = false;
			// INDEX = 0;
		}
	}

	public boolean sendStartSignal() {

		try {
			openConnect();// 建立连接

			sendOrder(1);// 发送打开命令

			getOrder(2);// 得到应答指令

		} catch (IOException e) {

			faultProcess(e);

			if (tryCount <= 3) {
				tryCount++;
				sendStartSignal();
			} else {
				tryCount = 1;
			}
			return false;
		}

		closeConnect();// 关闭连接

		System.out.println("starting the device successfully!");
		return true;
	}

	public boolean sendCloseSignal() {

		try {
			openConnect();// 建立连接

			sendOrder(5);// 发送请求命令码

			getOrder(6);// 解析应答端的应答

		} catch (IOException e) {

			faultProcess(e);

			if (tryCount <= 3) {
				tryCount++;
				sendCloseSignal();
			} else {
				tryCount = 1;
				return false;
			}
		}

		closeConnect();// 关闭连接

		System.out.println("closing the device successfully!");
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
		this.client = new Socket(ip, port);
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
		this.client = new Socket(ip, port);
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
			System.out.println("device not closed!");
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
				get_WHOLE_BYTE = true;
				condition.signalAll();
			} finally {
				lock.unlock();
			}
		}
	}

	private void faultProcess(IOException e1) {

		System.out.println(e1.toString());

		closeConnect();

		if (tryCount > 3) {
			return;
		}

		System.out.println("reconnecting.... " + tryCount + " times ");

		try {
			Thread.sleep(tryInterval);
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
