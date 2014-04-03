/*
 * Filename: ConfigReceiver.java
 * Copyright: ICT (c) 2012-10-25
 * Description: 是一个server，接收配置文件
 * Author: 25hours
 */
package ict.analyser.communication;

import ict.analyser.config.ConfigData;
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
import java.net.UnknownHostException;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class ConfigReceiver implements Runnable {
	private Socket client = null;// 连接到本服务器的客户端socket
	private static int PORT = 7890; // web发布与数据库板卡负责分发配置文件的端口
	private static int BUFFER_SIZE = 8192;// 缓冲区大小
	private Lock locker = null;// 加锁
	private PrintWriter writer = null;// 输出流到配置管理server
	private Condition condition = null;// 设置等待唤醒，相当于wait/notify
	private ServerSocket server = null;// 服务器socket
	private ConfigData configData = null;// 保存解析后得到的配置信息的类，主分析进程将读取
	private DataInputStream fileIn = null;// 输入流
	private DataOutputStream fileOut = null;// 输出流到本地文件
	private static String SAVE_PATH = "config.json";// 接收到的文件保存到的路径本地(待定)

	public ConfigReceiver() {
		locker = new ReentrantLock();// 初始化锁
		condition = locker.newCondition();// 初始化等待唤醒条件
		try {
			server = new ServerSocket(PORT);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void run() {
		while (true) {// 无限循环监听
			try {
				initTask();// 初始化一个socket和输入输出流
				getFile(); // 接收文件，写入本地文件，调用函数解析
			} catch (IOException e) {
				e.printStackTrace();
				continue;
			} finally {
				closeTask();// 关闭输入输出流和socket
			}
			processConfig();// 调用函数处理配置信息
		}
	}

	/**
	 * 初始化socket和输入输出流
	 * 
	 * @throws IOException
	 */
	private void initTask() throws IOException {
		// 建立socket连接
		try {
			client = server.accept();// 初始化一个socket

			fileIn = new DataInputStream(new BufferedInputStream(
					client.getInputStream()));

			fileOut = new DataOutputStream(new BufferedOutputStream(
					new BufferedOutputStream(new FileOutputStream(SAVE_PATH))));

			writer = new PrintWriter(client.getOutputStream(), true);

		} catch (UnknownHostException e1) {
			e1.printStackTrace();
		}

	}

	/**
	 * 从服务器接收配置文件，将内容写入本地文件中
	 * 
	 * @throws IOException
	 */
	public void getFile() throws IOException {
		byte[] buf = new byte[BUFFER_SIZE];// 开辟一个接收文件缓冲区

		int passedlen = 0;// 记录传输长度
		int totalLen = this.fileIn.readInt();

		if (totalLen == 0) {
			return;
		}

		int read = 0;
		// 获取文件
		while (passedlen < totalLen) {
			if (this.fileIn != null) {
				read = this.fileIn.read(buf);
			}

			passedlen += read;

			if (read == -1) {
				break;
			}

			this.fileOut.write(buf, 0, read);
		}
		System.out.println("配置文件接收了" + passedlen + "B");
		writer.println("ack");// 向服务器发送ack
	}

	/**
	 * 关闭socket和输入输出流
	 */
	public void closeTask() {
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
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * 将接收并保存的配置文件解析为ConfigData
	 */
	public void processConfig() {
		locker.lock();
		try {
			this.configData = FileProcesser.readConfigData(SAVE_PATH);// 调用处理config文件函数
																		// 写在FileProcesser里
			// this.configData.printDetail();// 打印config
			condition.signalAll();// 发送信号唤醒等待
		} finally {
			locker.unlock();
		}
	}

	/**
	 * @return Returns the
	 *         configData.如果configData这时候被锁了，就会阻塞调用getConfigData的函数，直到这个锁被unlock为止
	 */
	public ConfigData getConfigData() {
		locker.lock();
		// System.out.println("getConfigData  Lock");
		try {
			if (configData == null) {
				condition.await();
			}
			return configData;
		} catch (InterruptedException e) {
			e.printStackTrace();
			return null;
		} finally {
			locker.unlock();
		}

	}
}