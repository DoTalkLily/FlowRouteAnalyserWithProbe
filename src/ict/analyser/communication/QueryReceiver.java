package ict.analyser.communication;

/**
 * 修改记录: 20130515  bytes字段从数据库读用getLong
 *          20130531  支持跨周期流查询
 */
import ict.analyser.tools.IPTranslator;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.UnknownHostException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
//import java.io.DataInputStream;
//import java.io.DataOutputStream;
//import java.io.BufferedReader;
//import java.net.ServerSocket;
//import java.net.Socket;

public class QueryReceiver extends Thread {
	private static int lport = 3333;// 服务器监听的端口号
	private static int sport = 3334;// 向client发送的端口号
	// private ServerSocket server = null;
	// private Socket client = null;// 保存接收到连接的socket
	private DatagramSocket sendSocket = null;
	private DatagramSocket recvSocket = null;

	// private DataInputStream in = null;// 输入流
	// private DataOutputStream out = null;// 输出流
	private DatagramPacket in = null;
	private DatagramPacket out = null;
	private final byte[] inBuf = new byte[256];

	private int topN = 0;
	private long src = 0;
	private long dst = 0;
	private long spid = 0;
	private long epid = 0;
	private String str = null;
	private String type = null;// 流查询的类型，有ip, prefix, interface

	private String sql = null;
	private String dbconn = "jdbc:mysql://127.0.0.1:3306/netflow";
	private String username = "root";
	private String password = "qazwsx";
	private Connection connection = null;
	private Statement stmt = null;
	private ResultSet rs = null;

	public QueryReceiver() {
		try {
			// server = new ServerSocket(port);
			recvSocket = new DatagramSocket(lport);
			sendSocket = new DatagramSocket();
			in = new DatagramPacket(inBuf, inBuf.length);
			// byte[] outBuf = new byte[10000];
			// out = new DatagramPacket(outBuf, outBuf.length);

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void run() {
		while (true) {

			this.initTask();// 初始化socket、输入输出流和各个字段

			this.connectDB();// 连接数据库

			this.query();// 根据client的参数进行查询处理

			this.closeTask();// 关闭数据库、socket和输入输出流

		}

	}

	private void initTask() {
		try {
			// this.client = server.accept();
			// 获得IO句柄
			recvSocket.receive(in);
			str = new String(inBuf, 0, in.getLength());
			// this.in = new DataInputStream(this.client.getInputStream());
			// this.out = new DataOutputStream(this.client.getOutputStream());
			// 解析输入流，提取并初始化各个字段
			// str = in.readUTF();
			System.out.println(str);

			JSONObject jObject = new JSONObject(str);
			spid = jObject.getLong("stpid");
			epid = jObject.getLong("edpid");
			src = IPTranslator.calIPtoLong(jObject.getString("query"));
			dst = src;
			type = jObject.getString("type");
			topN = jObject.getInt("topN");
			System.out.println(src);

		} catch (JSONException e) {
			e.printStackTrace();
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void connectDB() {

		try {
			Class.forName("com.mysql.jdbc.Driver");
			this.connection = DriverManager.getConnection(dbconn, username,
					password);
		} catch (ClassNotFoundException cnfex) {
			System.err.println("装载JDBC驱动程序失败");
			cnfex.printStackTrace();
		} catch (SQLException sqlex) {
			System.err.println("无法连接数据库");
			sqlex.printStackTrace();
		}

	}

	// 多级别流查询
	private void query() {
		try {
			stmt = connection.createStatement();

			JSONObject jobj = new JSONObject();
			JSONObject resultJobj = new JSONObject();
			JSONArray srcArray = new JSONArray();
			JSONArray dstArray = new JSONArray();

			sql = "select pid, sum(bytes),srcIP, dstIP, path, protocol "
					+ "from (select * from netflow where " + "pid >= '" + spid
					+ "' " + "and pid<='" + epid + "' and src" + type + "='"
					+ src + "') "
					+ "temp group by srcIP, dstIP, srcPort, dstPort, "
					+ "startTime, endTime, protocol, output"
					+ " order by sum(bytes) desc limit " + topN + ";";
			System.out.println("src:" + sql);
			rs = stmt.executeQuery(sql);

			while (rs.next()) {

				jobj = new JSONObject();
				jobj.put("pid", rs.getLong("pid"));
				jobj.put("srcIP", IPTranslator.calLongToIp(rs.getLong("srcIP")));
				jobj.put("dstIP", IPTranslator.calLongToIp(rs.getLong("dstIP")));
				jobj.put("bytes", rs.getLong("sum(bytes)"));
				jobj.put("protocol", rs.getInt("protocol"));
				jobj.put("path", rs.getString("path"));

				srcArray.put(jobj);
			}
			resultJobj.put("src", srcArray);

			sql = "select pid, sum(bytes),srcIP, dstIP, path, protocol "
					+ "from (select * from netflow where " + "pid >= '" + spid
					+ "' " + "and pid<='" + epid + "' and dst" + type + "='"
					+ dst + "') "
					+ "temp group by srcIP, dstIP, srcPort, dstPort, "
					+ "startTime, endTime, protocol, input"
					+ " order by sum(bytes) desc limit " + topN + ";";
			System.out.println("dst:" + sql);
			rs = stmt.executeQuery(sql);

			while (rs.next()) {
				jobj = new JSONObject();
				jobj.put("pid", rs.getLong("pid"));
				jobj.put("srcIP", IPTranslator.calLongToIp(rs.getLong("srcIP")));
				jobj.put("dstIP", IPTranslator.calLongToIp(rs.getLong("dstIP")));
				jobj.put("bytes", rs.getLong("sum(bytes)"));
				jobj.put("protocol", rs.getInt("protocol"));
				jobj.put("path", rs.getString("path"));

				dstArray.put(jobj);
			}
			resultJobj.put("dst", dstArray);

			String strToSend = resultJobj.toString();
			out = new DatagramPacket(strToSend.getBytes(), strToSend.length(),
					in.getAddress(), sport); // 使用in中的ip
			System.out.println(in.getAddress());
			System.out.println(strToSend);
			System.out.println(strToSend.length());
			sendSocket.send(out);

			// out.writeUTF(resultJobj.toString());
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (JSONException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void closeTask() {
		try {
			this.connection.close();
		} catch (Exception e) {
			System.err.println("关闭数据库连接失败");
		}
		try {
//			 if (sendSocket != null) {
//			 sendSocket.close();
//			 }
//			 if (out != null) {
//			 out.close();
//			 }
//			 if (client != null) {
//			 client.close();
//			 }
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
	}
}
