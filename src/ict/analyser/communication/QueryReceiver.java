package ict.analyser.communication;

/**
 * 修改记录: 20130515  bytes字段从数据库读用getLong
 *         20130531  支持跨周期流查询
 */
import ict.analyser.database.DBOperator;
import ict.analyser.tools.IPTranslator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class QueryReceiver extends Thread {
	private static int port = 3333;// 服务器监听的端口号
	private Socket client = null;// 保存接收到连接的socket
	private PrintWriter out = null;// 输出流
	private BufferedReader in = null;// 输入流
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
			this.initTask();// 初始化socket、输入输出流和各个字段
			this.query();// 根据client的参数进行查询处理
			this.closeTask();// 关闭数据库、socket和输入输出流
		}

	}

	private void initTask() {
		try {
			this.client = server.accept();
			this.in = new BufferedReader(new InputStreamReader(
					this.client.getInputStream()));
			this.out = new PrintWriter(this.client.getOutputStream(), true);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// 多级别流查询
	private void query() {
		try {
			String queryStr = this.in.readLine();
			JSONObject queryObj = new JSONObject(queryStr);
			String queryType = queryObj.getString("type");

			if (queryType.equals("flow")) {
				queryFlow(queryObj);
			} else if (queryType.equals("link")) {
				queryLink(queryObj);
			}

		} catch (JSONException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void queryFlow(JSONObject queryObject) {
		int topN;
		int[] portArr;
		long startPid, endPid;
		JSONArray ports;
		JSONObject params;
		String level, src, dst;

		try {
			params = queryObject.getJSONObject("params");
			level = params.getString("level");
			ports = params.getJSONArray("ports");
			startPid = params.getLong("stpid");
			endPid = params.getLong("edpid");
			src = params.getString("src");
			dst = params.getString("dst");
			topN = params.getInt("topN");

			if (level == null || ports == null || ports.length() == 0
					|| startPid == 0 || endPid == 0 || topN <= 0) {// 如果参数有问题 报错
				out.println("wrong params");
				this.closeTask();
				return;
			}

			// 提取port
			int portLen = ports.length();
			portArr = new int[portLen];

			for (int i = 0; i < portLen; i++) {
				portArr[i] = (Integer) ports.get(i);
			}
		} catch (JSONException e1) {
			e1.printStackTrace();
			return;
		}

		String sql;
		String selectStr = "select sum(bytes),srcIP, dstIP,srcPort,dstPort, path, protocol,input,tos from netflow where ";
		String portArrStr = String.valueOf(portArr);
		String conditionStr = " pid >= " + startPid + " and pid <=" + endPid
				+ " and srcPort in " + portArrStr + " or dstPort in "
				+ portArrStr + " group by bytes desc limit " + topN + ";";

		String srcCondition = "", dstCondition = "";

		if (src == null && dst == null) {
			sql = selectStr + conditionStr;
		}

		if (src != null) {
			srcCondition = (level.equals("ip") ? " srcIP=" : " srcPrefix=")
					+ src;
		}

		if (dst != null) {
			dstCondition = (level.equals("ip") ? " dstIP=" : " dstPrefix=")
					+ src;
		}

		sql = selectStr + srcCondition + " and " + dstCondition + conditionStr;// 这里需求待确认
		ResultSet result = DBOperator.queryFlow(sql);

		if (result == null) {
			out.println("query error");
			this.closeTask();
			return;
		}

		String resultStr = getResultJson(result);
		out.println(resultStr.toString());
		closeTask();
	}

	private String getResultJson(ResultSet result) {
		JSONArray resultObj = new JSONArray();
		JSONObject item;

		try {
			while (result.next()) {
				item = new JSONObject();
				item.put("srcIp",
						IPTranslator.calLongToIp(result.getLong("srcIP")));
				item.put("dstIp",
						IPTranslator.calLongToIp(result.getLong("dstIP")));
				item.put("srcPort", result.getInt("srcPort"));
				item.put("dstPort", result.getInt("dstPort"));
				item.put("protocal", result.getInt("protocal"));
				item.put("index", result.getInt("input"));
				item.put("tos", result.getInt("tos"));
				item.put("bytes", result.getLong("bytes"));
				item.put("path", result.getString("path"));
				resultObj.put(item);
			}
			return resultObj.toString();
		} catch (JSONException e) {
			e.printStackTrace();
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			this.closeTask();
		}
		return null;
	}

	private void queryLink(JSONObject queryObject) {
		int topN;
		long pid;
		JSONObject params;
		String sql;
		String group;
		String routerA, routerB;

		try {
			group = queryObject.getString("group");
			params = queryObject.getJSONObject("params");
			pid = params.getLong("pid");
			routerA = params.getString("routerA");
			routerB = params.getString("routerB");
			topN = params.getInt("topN");

			String selectStr = "select sum(bytes),srcIP, dstIP,path from netflow where pid="
					+ pid;
			String otherCondition = " order by sum(bytes) desc limit " + topN
					+ ";";
			String groupCondition = "";

			if (group.equals("ip2")) {// 按照ip二元组聚合
				groupCondition = " group by srcIP, dstIP ";
				long srcRouter = IPTranslator.calIPtoLong(routerA);
				long dstRouter = IPTranslator.calIPtoLong(routerB);

				sql = selectStr + " and srcRouter=" + srcRouter + " dstRouter="
						+ dstRouter + groupCondition + otherCondition;
				ResultSet set1 = DBOperator.queryFlow(sql);

				sql = selectStr + " and srcRouter" + dstRouter + " dstRouter="
						+ srcRouter + group + otherCondition;
				ResultSet set2 = DBOperator.queryFlow(sql);

				JSONObject resultObj = new JSONObject();
				resultObj.put("routerA", routerA);
				resultObj.put("routerB", routerB);
				JSONArray obverse = new JSONArray();
				JSONObject item;

				while (set1.next()) {
					item = new JSONObject();
					item.put("srcIp",
							IPTranslator.calLongToIp(set1.getLong("srcIP")));
					item.put("dstIp",
							IPTranslator.calLongToIp(set1.getLong("dstIP")));
					item.put("bytes", set1.getLong("bytes"));
					item.put("path", set1.getString("path"));
					obverse.put(item);
				}

				JSONArray reverse = new JSONArray();

				while (set2.next()) {
					item = new JSONObject();
					item.put("srcIp",
							IPTranslator.calLongToIp(set1.getLong("srcIP")));
					item.put("dstIp",
							IPTranslator.calLongToIp(set1.getLong("dstIP")));
					item.put("bytes", set1.getLong("bytes"));
					item.put("path", set1.getString("path"));
					reverse.put(item);
				}

				resultObj.put("obverse", obverse);
				resultObj.put("reverse", reverse);

				out.println(resultObj.toString());
			} else {
				if (group.equals("ip7")) {// 按照ip7元组聚合
					groupCondition = " group by srcIP, dstIP, srcPort, dstPort, protocol,input,tos ";
				} else if (group.equals("protocal")) {// 按照业务聚合
					groupCondition = " group by protocal ";
				}
				sql = selectStr + groupCondition + otherCondition;
				ResultSet result = DBOperator.queryFlow(sql);

				if (result == null) {
					out.println("query error");
					this.closeTask();
					return;
				}

				String resultStr = getResultJson(result);
				out.println(resultStr.toString());
			}

		} catch (SQLException e) {
			e.printStackTrace();
		} catch (JSONException e) {
			e.printStackTrace();
		} finally {
			this.closeTask();
		}
	}

	private void closeTask() {
		try {
			if (out != null) {
				out.close();
			}
			if (in != null) {
				in.close();
			}
			if (client != null) {
				client.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
