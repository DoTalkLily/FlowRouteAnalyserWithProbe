package ict.analyser.communication;

/**
 * 修改记录: 20130515  bytes字段从数据库读用getLong
 *         20130531  支持跨周期流查询
 */
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class QueryReceiver implements Runnable {
	private static int port = 3333;// 服务器监听的端口号
	private ServerSocket server = null;

	public QueryReceiver() {
		try {
			server = new ServerSocket(port);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void run() {
		while (true) {
			createQueryTask();// 初始化socket、输入输出流和各个字段
		}
	}

	private void createQueryTask() {
		try {
			Socket client = this.server.accept();
			QueryTask task = new QueryTask(client);
			new Thread(task).start();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
