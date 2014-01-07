package ict.analyser.communication;

/*
 * Filename: ResultSender.java
 * Copyright: ICT (c) 2012-11-13
 * Description: 发送flow分析结果给综合分析板卡
 * Author: 25hours
 */
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-13
 * @version 1.1, 2013-2-18 加出错重连接机制和数据传输中断处理机制
 */
public class ResultSender implements Runnable {
	private int port = 0; // 综合分析板卡端口号
	private long pid = 0; // pid
	private String ip = null; // 综合分析板卡ip地址
	private Socket sender = null; // 发送结果socket
	private String filePath = null;// 文件路径
	private DataInputStream is = null;// 输入流
	private DataOutputStream os = null;// 输出流
	private static int tryCount = 1;// 如果连接失败，或者读数据失败，尝试重连接的次数
	private static int tryInterval = 3 * 1000;// 两次尝试重连的时间间隔，单位： 秒

	public ResultSender(long pid, int port, String ip, String filePath) {// 初始化时顺便赋值
		this.ip = ip;
		this.pid = pid;
		this.port = port;
		this.filePath = filePath;
	}

	@Override
	public void run() {
		sendFile();
	}

	/**
	 * 发送文件给综合分析板卡
	 */
	public void sendFile() {

		try {
			openConnect();

			sendData();

		} catch (IOException e) {
			faultProcess(e);

			if (tryCount <= 3) {
				tryCount++;
				sendFile();
			} else {
				tryCount = 1;
			}
			return;
		} finally {
			closeConnect();// 关闭连接
		}
	}

	private void openConnect() throws IOException {
		sender = new Socket(this.ip, this.port);// 初始化socket
		os = new DataOutputStream(this.sender.getOutputStream());

		if (filePath != null) {
			is = new DataInputStream(new BufferedInputStream(
					new FileInputStream(this.filePath)));
		} else {
			is = new DataInputStream(this.sender.getInputStream());
		}

	}

	private void closeConnect() {
		try {
			if (os != null)
				os.close();
			if (is != null)
				is.close();
			if (sender != null)
				sender.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void sendData() throws IOException {
		if (this.filePath != null) {
			// 缓冲区大小
			int bufferSize = 8192;
			// 缓冲区
			byte[] buf = new byte[bufferSize];
			// 传输文件
			while (true) {
				int read = 0;
				if (is != null) {
					read = is.read(buf);
				}

				if (read == -1) {
					break;
				}
				os.write(buf, 0, read);
				os.flush();
			}
		} else {
			os.writeBytes(pid + "");// 这里当第一个周期拓扑文件为空，只上报pid给综合分析，当然：pid也有可能为空
			os.flush();
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
}
