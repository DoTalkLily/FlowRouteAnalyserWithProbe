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
		long startPid, endPid;
		String src, dst, level, protocal;

		// 字段提取
		try {
			JSONObject params = queryObject.getJSONObject("params");
			level = params.getString("level");
			protocal = params.getString("protocal");
			startPid = params.getLong("stpid");
			endPid = params.getLong("edpid");
			src = params.getString("src");
			dst = params.getString("dst");
			topN = params.getInt("topN");

			if (level == null || protocal == null || startPid == 0
					|| endPid == 0 || topN <= 0) {// 如果参数有问题 报错
				out.println(new JSONArray());
				return;
			}
		} catch (JSONException e1) {
			e1.printStackTrace();
			out.println(new JSONArray());
			return;
		}

		// 判断查询表数目
		long spid = startPid / 10000;
		long epid = endPid / 10000;
		String condition = "";

		if ((src == null && dst == null)
				|| (src.length() == 0 && dst.length() == 0)) {
			out.println(new JSONArray());
			return;
		}

		if (src.length() != 0) {
			condition = " and "
					+ ((level.equals("ip") ? " srcIP=" : " srcPrefix=") + IPTranslator
							.calIPtoLong(src));
		}

		if (dst.length() != 0) {
			condition += " and "
					+ ((level.equals("ip") ? " dstIP=" : " dstPrefix=") + IPTranslator
							.calIPtoLong(dst));
		}

		String selectStr = "select bytes,srcIP, dstIP,srcPort,dstPort, path, protocal,input,tos,routerIp,srcMask,dstMask,srcAS,dstAS from ";
		condition += getPortCondition(protocal);
		String subTable = "";
		String whereCondition = "";
		String table1 = "netflow" + spid;
		String table2 = "netflow" + (spid + 1);
		String table3 = "netflow" + epid;

		if (spid == epid) {// 一张表内
			int startHour = Utils.pid2HourOfYear(startPid);
			int endHour = Utils.pid2HourOfYear(endPid);
			subTable = table1;
			whereCondition = " where hour>=" + startHour + " and hour<="
					+ endHour + " and pid >= " + startPid + " and pid <="
					+ endPid + condition;
		} else if ((spid + 1) == epid) {// 两张表
			subTable = " ((" + selectStr + table1 + " where pid>=" + startPid
					+ condition + ") union all (" + selectStr + table3
					+ " where pid<=" + endPid + condition + ")) as subTable ";
		} else if ((spid + 2) == epid) {// 三张表
			subTable = " ((" + selectStr + table1 + " where pid>=" + startPid
					+ condition + ") union all (" + selectStr + table2
					+ " where " + condition.trim().substring(4)
					+ ") union all (" + selectStr + table3 + " where pid<="
					+ endPid + condition + ")) as subTable ";
		} else {// 只支持两天范围内数据查询
			out.println(new JSONArray());
			return;
		}

		String otherCondition = " group by srcIP, dstIP,srcPort,dstPort,protocal order by byte desc limit "
				+ topN + ";";

		selectStr = "select sum(bytes) as byte,srcIP, dstIP,srcPort,dstPort, path, protocal,input,tos,routerIp,srcMask,dstMask,srcAS,dstAS from ";
		String sql = selectStr + subTable + whereCondition + otherCondition;

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
		String selectStr = "select sum(bytes) as byte,srcIP, dstIP,srcMask,dstMask,srcAS,dstAS,path from netflow"
				+ (pid / 10000) + " where pid=" + pid;
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
		String selectStr = "select sum(bytes) as byte,srcIP, dstIP,srcMask,dstMask,srcPort,dstPort,srcAS,dstAS,input,tos,path,protocal from netflow"
				+ (pid / 10000) + " where pid=" + pid;
		String tailCondition = " order by sum(bytes) desc " + ";";

		String sql = selectStr + " and srcIP=" + IPTranslator.calIPtoLong(ipA)
				+ " and dstIP=" + IPTranslator.calIPtoLong(ipB) + tailCondition;

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
		String selectStr = "select bytes as byte,srcIP, dstIP,srcMask,dstMask,srcPort,dstPort,srcAS,dstAS,input,tos,path,protocal from netflow"
				+ (pid / 10000) + " where pid=" + pid;
		String portCondition = getPortCondition(protocal);
		String tailCondition = " order by bytes desc limit " + topN + ";";
		String sql = selectStr + " and path like '%" + routerA + "%" + routerB
				+ "%' " + portCondition + tailCondition;

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

	private String getPortCondition(String protocal) {
		// 提取port
		if ("all".equals(protocal)) {
			return "";
		}

		String portList = "";
		String portCondition = "";
		ArrayList<Integer> ports = ConfigData.getPortStrByProtocal(protocal);

		if (ports == null || ports.size() == 0) {// 当配置文件没接到或者配置中端口——协议映射没给用传统方式
			System.out.println("ports for " + protocal + " cannot be found!");
		} else {
			int portLen = ports.size();
			portList = "(" + ports.get(0);

			for (int i = 1; i < portLen; i++) {
				portList += "," + ports.get(i);
			}

			portList += ") ";
			if ("other".equals(protocal)) {
				portCondition += " and srcPort not in " + portList
						+ " and dstPort not in " + portList;
			} else {
				portCondition += " and (srcPort in " + portList
						+ " or dstPort in " + portList + ") ";
			}
		}
		return portCondition;
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
