/*
 * Filename: QueryTask.java
 * Copyright: ICT (c) 2013-12-3
 * Description: 
 * Author: Lily
 */
package ict.analyser.communication;

import ict.analyser.config.ConfigData;
import ict.analyser.database.DBOperator;
import ict.analyser.tools.IPTranslator;
import ict.analyser.tools.Utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * 
 * 
 * @author Lily
 * @version 1.0, 2013-12-3
 */
public class QueryTask implements Runnable {
	private Socket client = null;// 保存接收到连接的socket
	private PrintWriter out = null;// 输出流
	private BufferedReader in = null;// 输入流

	public QueryTask(Socket client) {
		this.client = client;
	}

	@Override
	public void run() {
		initTask();// 初始化socket、输入输出流和各个字段
		query();// 根据client的参数进行查询处理
		closeTask();// 关闭数据库、socket和输入输出流
	}

	private void initTask() {
		System.out.println("query init");
		try {
			this.in = new BufferedReader(new InputStreamReader(
					this.client.getInputStream()));
			this.out = new PrintWriter(this.client.getOutputStream(), true);
		} catch (IOException e) {
			out.println(new JSONArray());
			e.printStackTrace();
		}
	}

	// 多级别流查询
	private void query() {
		System.out.println("querying");
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
		long startPid;
		long endPid;
		String protocal;
		JSONObject params;
		String level, src, dst;
		String whereCondition = "";
		String sql;
		String selectStr = "select sum(bytes) as byte,srcIP, dstIP,srcPort,dstPort, path, protocal,input,tos,routerIp,srcMask,dstMask,srcAS,dstAS from netflow where ";

		try {
			params = queryObject.getJSONObject("params");
			level = params.getString("level");
			protocal = params.getString("protocal");
			startPid = params.getLong("stpid");
			endPid = params.getLong("edpid");
			src = params.getString("src");
			dst = params.getString("dst");
			topN = params.getInt("topN");

			if (level == null || protocal == null || startPid == 0
					|| endPid == 0 || topN <= 0) {// 如果参数有问题 报错
				// out.println("wrong params");
				out.println(new JSONArray());
				return;
			}

			int startHour = Utils.pid2HourOfYear(startPid);
			int endHour = Utils.pid2HourOfYear(endPid);

			whereCondition = " hour>=" + startHour + " and hour<=" + endHour
					+ " and pid >= " + startPid + " and pid <=" + endPid;
			// 提取port
			if (!"all".equals(protocal)) {
				String portCondition = "";
				ArrayList<Integer> ports = ConfigData
						.getPortStrByProtocal(protocal);

				if (ports == null || ports.size() == 0) {// 当配置文件没接到或者配置中端口——协议映射没给用传统方式
					System.out.println("ports for " + protocal
							+ " cannot be found!");
				} else {
					int portLen = ports.size();
					portCondition = "(" + ports.get(0);

					for (int i = 1; i < portLen; i++) {
						portCondition += "," + ports.get(i);
					}

					portCondition += ") ";
					if ("other".equals(protocal)) {
						whereCondition += " and srcPort not in "
								+ portCondition + " and dstPort not in "
								+ portCondition;
					} else {
						whereCondition += " and (srcPort in " + portCondition
								+ " or dstPort in " + portCondition + ") ";
					}
				}
			}
		} catch (JSONException e1) {
			e1.printStackTrace();
			out.println(new JSONArray());
			return;
		}

		String tailCondition = " group by srcIP, dstIP,srcPort,dstPort,input,protocal,tos order by byte desc limit "
				+ topN + ";";

		if (src == null && dst == null) {
			sql = selectStr + whereCondition + tailCondition;
		} else if (src != null && dst != null) {
			long srcLong = IPTranslator.calIPtoLong(src);
			String srcCondition = (level.equals("ip") ? " srcIP="
					: " srcPrefix=") + srcLong;

			long dstLong = IPTranslator.calIPtoLong(dst);
			String dstCondition = (level.equals("ip") ? " dstIP="
					: " dstPrefix=") + dstLong;

			sql = selectStr + whereCondition + " and " + srcCondition + " and "
					+ dstCondition + tailCondition;// 这里需求待确认
		} else {
			// out.println("wrong params");
			out.println(new JSONArray());
			return;
		}

		System.out.println(sql);
		ResultSet result = DBOperator.queryFlow(sql);

		if (result == null) {
			// out.println("query error");
			out.println(new JSONArray());
			return;
		}

		String resultStr = getResultJson(result);
		out.println(resultStr.toString());
		System.out.println(resultStr.toString());
	}

	private String getResultJson(ResultSet result) {
		JSONArray resultObj = new JSONArray();
		JSONObject item;

		try {
			while (result.next()) {
				item = new JSONObject();

				// 如果是返回空记录
				if (result.getLong("srcIP") == 0) {
					return new JSONArray().toString();
				}

				item.put("srcIp",
						IPTranslator.calLongToIp(result.getLong("srcIP")));
				item.put("dstIp",
						IPTranslator.calLongToIp(result.getLong("dstIP")));
				item.put("srcPort", result.getInt("srcPort"));
				item.put("dstPort", result.getInt("dstPort"));
				item.put("srcMask", result.getByte("srcMask"));
				item.put("dstMask", result.getByte("dstMask"));
				item.put("srcAS", result.getInt("srcAS"));
				item.put("dstAS", result.getInt("dstAS"));
				item.put("protocal", result.getInt("protocal"));
				item.put("index", result.getInt("input"));
				item.put("tos", result.getInt("tos"));
				item.put("bytes", result.getLong("byte"));
				item.put("path", result.getString("path"));
				resultObj.put(item);
			}
			// obj.put("result", resultObj);
			return resultObj.toString();
		} catch (JSONException e) {
			e.printStackTrace();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}

	private void queryLink(JSONObject queryObject) {
		String group = null;
		try {
			group = queryObject.getString("group");
			JSONObject params = queryObject.getJSONObject("params");

			if ("ip2".equals(group)) {
				queryIp2(params);
			} else if ("ip7".equals(group)) {
				queryIp7(params);
			} else if ("protocol".equals(group)) {
				queryProtocal(params);
			} else {
				out.println(new JSONArray());
			}
		} catch (SQLException e) {
			out.println(new JSONArray());
			e.printStackTrace();
		} catch (JSONException e) {
			out.println(new JSONArray());
			e.printStackTrace();
		}
	}

	/**
	 * 
	 * 
	 * @param queryObject
	 * @throws JSONException
	 * @throws SQLException
	 */
	private void queryIp2(JSONObject params) throws JSONException, SQLException {
		int topN = params.getInt("topN");
		long pid = params.getLong("pid");
		String routerA = params.getString("routerA");
		String routerB = params.getString("routerB");
		String selectStr = "select sum(bytes) as byte,srcIP, dstIP,srcMask,dstMask,srcAS,dstAS,path from netflow where pid="
				+ pid;
		String tailCondition = " order by sum(bytes) desc limit " + topN + ";";
		String groupCondition = " group by srcIP, dstIP ";
		String sql = selectStr + " and path like '%" + routerA + "%" + routerB
				+ "%' " + groupCondition + tailCondition;

		System.out.println("sql1:" + sql);
		ResultSet set1 = DBOperator.queryFlow(sql);
		sql = selectStr + " and path like '%" + routerB + "%" + routerA + "%' "
				+ groupCondition + tailCondition;
		System.out.println("sql2:" + sql);
		ResultSet set2 = DBOperator.queryFlow(sql);

		JSONObject resultObj = new JSONObject();
		resultObj.put("routerA", routerA);
		resultObj.put("routerB", routerB);
		JSONArray obverse = new JSONArray();
		JSONObject item;

		while (set1.next()) {
			item = new JSONObject();
			item.put("srcIp", IPTranslator.calLongToIp(set1.getLong("srcIP")));
			item.put("dstIp", IPTranslator.calLongToIp(set1.getLong("dstIP")));
			item.put("srcMask", set1.getByte("srcMask"));
			item.put("dstMask", set1.getByte("dstMask"));
			item.put("srcAS", set1.getInt("srcAS"));
			item.put("dstAS", set1.getInt("dstAS"));
			item.put("bytes", set1.getLong("byte"));
			item.put("path", set1.getString("path"));
			obverse.put(item);
		}

		JSONArray reverse = new JSONArray();

		while (set2.next()) {
			item = new JSONObject();
			item.put("srcIp", IPTranslator.calLongToIp(set2.getLong("srcIP")));
			item.put("dstIp", IPTranslator.calLongToIp(set2.getLong("dstIP")));
			item.put("srcMask", set2.getByte("srcMask"));
			item.put("dstMask", set2.getByte("dstMask"));
			item.put("srcAS", set2.getInt("srcAS"));
			item.put("dstAS", set2.getInt("dstAS"));
			item.put("bytes", set2.getLong("byte"));
			item.put("path", set2.getString("path"));
			reverse.put(item);
		}

		resultObj.put("obverse", obverse);
		resultObj.put("reverse", reverse);
		out.println(resultObj.toString());
		System.out.println(resultObj.toString());
	}

	/**
	 * 
	 * 
	 * @param queryObject
	 * @throws JSONException
	 */
	private void queryIp7(JSONObject params) throws JSONException {
		long pid = params.getLong("pid");

		String ipA = params.getString("ipA");
		String ipB = params.getString("ipB");
		String selectStr = "select sum(bytes) as byte,srcIP, dstIP,srcMask,dstMask,srcPort,dstPort,srcAS,dstAS,input,tos,path,protocal from netflow where pid="
				+ pid;
		String tailCondition = " order by sum(bytes) desc " + ";";
		// String groupCondition =
		// " group by srcIP, dstIP, srcPort, dstPort, protocal,input,tos ";
		String groupCondition = "";
		String sql = selectStr + " and srcIP=" + IPTranslator.calIPtoLong(ipA)
				+ " and dstIP=" + IPTranslator.calIPtoLong(ipB)
				+ groupCondition + tailCondition;

		System.out.println(sql);
		ResultSet result = DBOperator.queryFlow(sql);

		if (result == null) {
			out.println(new JSONArray());
			return;
		}
		String resultStr = getResultJson(result);
		out.println(resultStr.toString());
		System.out.println(resultStr.toString());
	}

	/**
	 * 
	 * 
	 * @param queryObject
	 * @throws JSONException
	 */
	private void queryProtocal(JSONObject params) throws JSONException {
		int topN = params.getInt("topN");
		long pid = params.getLong("pid");

		String protocal = params.getString("protocal");
		String routerA = params.getString("routerA");
		String routerB = params.getString("routerB");
		String selectStr = "select bytes as byte,srcIP, dstIP,srcMask,dstMask,srcPort,dstPort,srcAS,dstAS,input,tos,path,protocal from netflow where pid="
				+ pid;

		String groupCondition = "";

		if (!"all".equals(protocal)) {
			String portCondition = "";
			ArrayList<Integer> ports = ConfigData
					.getPortStrByProtocal(protocal);

			if (ports == null || ports.size() == 0) {// 当配置文件没接到或者配置中端口——协议映射没给用传统方式
				System.out.println("ports for " + protocal
						+ " cannot be found!");
			} else {
				int portLen = ports.size();
				portCondition = "(" + ports.get(0);

				for (int i = 1; i < portLen; i++) {
					portCondition += "," + ports.get(i);
				}

				portCondition += ") ";
				if ("other".equals(protocal)) {
					groupCondition = " and srcPort not in " + portCondition
							+ " and dstPort not in " + portCondition;
				} else {
					groupCondition = " and (srcPort in " + portCondition
							+ " or dstPort in " + portCondition + ") ";
				}
			}
		}

		// ArrayList<Integer> ports = new ArrayList<Integer>();
		// ports.add(8080);
		// ports.add(80);

		String tailCondition = " order by bytes desc limit " + topN + ";";
		String sql = selectStr + " and path like '%" + routerA + "%" + routerB
				+ "%' " + groupCondition + tailCondition;

		System.out.println(sql);
		ResultSet result = DBOperator.queryFlow(sql);

		if (result == null) {
			// out.println("query error");
			out.println(new JSONArray());
			return;
		}

		String resultStr = getResultJson(result);
		out.println(resultStr.toString());
		System.out.println(resultStr.toString());
	}

	private void closeTask() {
		System.out.println("query close");
		try {
			if (in != null) {
				in.close();
			}
			if (out != null) {
				out.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
