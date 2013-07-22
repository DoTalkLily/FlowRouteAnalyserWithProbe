/* 
 * Filename: FileProcesser.java
 * Description: Parse JSON files
 * @author: Liu Xiang
 * @version 1.0, 2012-10-14
 */

package ict.analyser.tools;

import ict.analyser.flow.TrafficLink;
import ict.analyser.isistopo.IsisRouter;
import ict.analyser.isistopo.IsisTopo;
import ict.analyser.isistopo.Reachability;
import ict.analyser.ospftopo.AsExternalLSA;
import ict.analyser.ospftopo.InterAsLink;
import ict.analyser.ospftopo.Link;
import ict.analyser.ospftopo.OspfRouter;
import ict.analyser.ospftopo.OspfTopo;
import ict.analyser.statistics.StatisticItem;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class FileProcesser {

	// parameters:
	// The location of JSON file
	public OspfTopo readOspfTopo(String filePath) {
		JSONObject jObject = null;
		OspfTopo topo = new OspfTopo();
		int size = 0;
		int asNumber = 0;
		long pid = 0;
		int linkId = 0;
		int metric = 0;
		long prefix = 0;
		long rid = 0;
		long nAsNumber = 0;
		String area = null;
		String mask = null;
		String routerId = null;
		String nRouterId = null;
		String interfaceIP = null;
		OspfRouter router = null;
		Link link = null;

		try {
			String topoString = "";
			BufferedReader br = new BufferedReader(new FileReader(filePath));
			String r = br.readLine();
			while (r != null) {
				topoString += r;
				r = br.readLine();
			}
			br.close();
			jObject = new JSONObject(topoString);

			// asNumber
			asNumber = jObject.getInt("asNumber");
			topo.setAsNumber(asNumber); // asNumber
			System.out.println("asNumber:" + asNumber);
			// topo
			JSONObject topoObj = jObject.getJSONObject("Topo");
			// pid
			pid = topoObj.getLong("pid");
			System.out.println("pid:" + pid);
			topo.setPeriodId(pid);
			// nodes
			JSONArray nodes = topoObj.getJSONArray("nodes");
			size = nodes.length();
			long ip = 0;

			for (int i = 0; i < size; i++) {
				router = new OspfRouter();
				JSONObject node = nodes.getJSONObject(i);
				routerId = node.getString("routerId");
				rid = IPTranslator.calIPtoLong(routerId);
				router.setRouterId(rid); // routerId

				JSONArray neighbors = node.getJSONArray("neighbors");
				int size1 = neighbors.length();
				for (int j = 0; j < size1; j++) {
					JSONObject neighbor = neighbors.getJSONObject(j);
					linkId = neighbor.getInt("id");
					area = neighbor.getString("area");
					interfaceIP = neighbor.getString("interfaceIP");
					mask = neighbor.getString("mask");
					nRouterId = neighbor.getString("nRouterId");
					metric = neighbor.getInt("metric");
					if (linkId != 0 && area != null && interfaceIP != null
							&& mask != null && nRouterId != null) {
						ip = IPTranslator.calIPtoLong(interfaceIP);
						link = new Link();
						link.setMyId(rid);
						link.setLinkId(linkId); // id
						link.setArea(area); // area
						link.setMyInterIp(ip); // interfaceIp
						link.setMask(IPTranslator.calIPtoLong(mask)); // mask
						link.setNeighborId(IPTranslator.calIPtoLong(nRouterId)); // nRouterId
						link.setMetric(metric); // metric
						router.addArea(area);
						router.setLink(link);
						// topo.setMapLinkIdByte(linkId);
						topo.setMapLidTraffic(linkId);
						// 添加到保存as内路由器ip——rid映射中
						topo.setMapIpRouterid(ip, rid);

						// System.out.println("ip:" +
						// IPTranslator.calLongToIp(ip)
						// + "  id:" + IPTranslator.calLongToIp(rid));
						// System.out.println("aaaaaaaa router id:"+routerId+"  neighbor id:"+
						// nRouterId+"  neighbor ip:" +
						// interfaceIP
						// + " mask :" + mask);

					}
				}
				topo.setRidRouter(rid, router);
				// System.out.println("rid add:" +
				// IPTranslator.calLongToIp(rid));

			}
			// stubs
			JSONArray stubs = topoObj.getJSONArray("stubs");
			size = stubs.length();
			for (int i = 0; i < size; i++) {
				JSONObject stub = stubs.getJSONObject(i);
				routerId = stub.getString("routerId");
				prefix = stub.getLong("prefix");
				mask = stub.getString("mask");
				if (routerId != null && prefix != 0 && mask != null) {
					topo.setMapPrefixRouterId(prefix,
							IPTranslator.calIPtoLong(routerId));
//					 System.out.println("prefix:"
//					 + IPTranslator.calLongToIp(prefix) + "  router id"
//					 + routerId);
				}
			}
			// asbr
			JSONArray asbrs = topoObj.getJSONArray("asbr");
			rid = 0;
			ip = 0;
			int input = 0;
			long masklong = 0;
			String ipstr = null;
			InterAsLink interLink = null;

			size = asbrs.length();

			for (int i = 0; i < asbrs.length(); i++) {
				interLink = new InterAsLink();
				JSONObject asbr = asbrs.getJSONObject(i);
				linkId = asbr.getInt("linkId");
				routerId = asbr.getString("routerId");
				interfaceIP = asbr.getString("interfaceIP");
				mask = asbr.getString("mask");
				nRouterId = asbr.getString("nRouterId");
				ipstr = asbr.getString("nInterfaceIP");
				nAsNumber = asbr.getInt("nAsNumber");
				metric = asbr.getInt("metric");
				input = asbr.getInt("input");

				if (linkId != 0 && routerId != null && interfaceIP != null
						&& mask != null && nRouterId != null && nAsNumber != 0
						&& input >= 0) {

					// linkId
					// topo.setMapLinkIdByte(linkId);
					topo.setMapLidTraffic(linkId);
					interLink.setLinkId(linkId);
					// routerId
					rid = IPTranslator.calIPtoLong(routerId);// 这里的routerId是邻居as的asbr的rid
					interLink.setMyBrId(rid);
					// interLink.setNeighborBrId(rid);
					// interfaceIp
					ip = IPTranslator.calIPtoLong(interfaceIP);// 这里的interfaceip是邻居as的asbr的接口ip
					interLink.setMyInterIp(ip);
					// interLink.setNeighborBrIp(ip);
					// mask
					masklong = IPTranslator.calIPtoLong(mask);
					interLink.setMask(masklong);
					// nRouterId
					rid = IPTranslator.calIPtoLong(nRouterId);// 这里“nRouterId”是本as的asbr的id
					interLink.setNeighborBrId(rid);
					// interLink.setMyBrId(rid);
					// nInterfaceIP
					ip = IPTranslator.calIPtoLong(ipstr);// 这里的“nInterfaceIP”是本as的asbr的接口ip
					interLink.setNeighborBrIp(ip);
					// interLink.setMyInterIp(ip);
					// nAsNumber
					interLink.setNeighborAS(nAsNumber);
					// metric
					interLink.setMetric(metric);
					// input
					interLink.setInput(input);

					topo.setMapIpRouterid(interLink.getMyInterIp(),
							interLink.getMyBrId());// 域内as内的所有ip——rid映射
					topo.setMapAsbrIpRouterId(interLink.getMyInterIp(),
							interLink.getMyBrId(), input, linkId);// 设置边界路由器ip——id映射
					topo.setInterAsLinks(interLink);// 设置边界链路
					topo.setMapASBRIpLinkId(interLink.getMyInterIp(), linkId);// 边界路由器ip——链路ip映射，两端的ip都存
					topo.setMapASBRIpLinkId(interLink.getNeighborBrIp(), linkId);
					// topo.setMapInputLinkid(rid, input, linkId);
				}
			}

			// asExternalLSA
			int externalType = 2;
			String nexthop = null;
			String prefixStr = null;
			AsExternalLSA asExternalLsa = null;
			JSONArray asExternalArr = jObject.getJSONArray("asExternalLSA");
			size = asExternalArr.length();

			for (int j = 0; j < size; j++) {
				JSONObject asExternalObj = asExternalArr.getJSONObject(j);
				asExternalLsa = new AsExternalLSA();
				routerId = asExternalObj.getString("advRouter");
				prefixStr = asExternalObj.getString("linkStateId");
				mask = asExternalObj.getString("networkMask");
				externalType = asExternalObj.getInt("externalType");
				metric = asExternalObj.getInt("metric");
				nexthop = asExternalObj.getString("forwardingAddress");
				if (routerId != null && prefixStr != null && mask != null
						&& externalType != 0 && nexthop != null) {
					asExternalLsa.setAdvRouter(IPTranslator
							.calIPtoLong(routerId)); // advRouter
					asExternalLsa.setLinkStateId(IPTranslator
							.calIPtoLong(prefixStr)); // linkStateId
					asExternalLsa
							.setNetworkMask(IPTranslator.calIPtoLong(mask)); // networkMask
					asExternalLsa.setExternalType(externalType); // externalType
					asExternalLsa.setMetric(metric); // metric
					asExternalLsa.setForwardingAddress(IPTranslator
							.calIPtoLong(nexthop)); // forwardingAddress
					topo.addAsExternalLSA(asExternalLsa);
				}
			}

		} catch (IOException e) {
			e.printStackTrace();
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return topo;
	}

	public IsisTopo readIsisTopo(String filePath) {

		int level = 0;
		int metric = 0;
		int linkId = 0;
		int sysType = 0;
		long rid = 0;
		long prefix = 0;
		String sysId = null;
		String nSysId = null;
		Link link = null;
		IsisRouter router = null;
		IsisTopo topo = new IsisTopo();
		ArrayList<Long> brIds = new ArrayList<Long>();
		JSONObject jObject = null;

		try {
			String topoString = "";
			BufferedReader br = new BufferedReader(new FileReader(filePath));
			String r = br.readLine();
			while (r != null) {
				topoString += r;
				r = br.readLine();
			}
			br.close();
			jObject = new JSONObject(topoString);

			level = jObject.getInt("level");

			if (level != 2 && level != 1) {
				return null;
			}

			String areaId = jObject.getString("areaId");

			if (areaId == null) {
				return null;
			}

			topo.setAreaId(areaId);

			JSONObject jTopo = jObject.getJSONObject("Topo");
			long pid = jTopo.getLong("pid");
			topo.setPid(pid);
			topo.setNetworkType(level);
			System.out.println("pid : " + pid);

			JSONArray nodes = jTopo.getJSONArray("nodes");
			int size = nodes.length();
			int nSize = 0;

			for (int i = 0; i < size; i++) {
				router = new IsisRouter();
				JSONObject node = nodes.getJSONObject(i);
				sysType = node.getInt("sysType");

				router.setLevel(sysType);

				sysId = node.getString("sysId");

				// System.out.println("sysid:" + sysId);
				if (sysId == null) {
					return null;
				}

				rid = IPTranslator.calSysIdtoLong(sysId);

				if (sysType == 3) {
					brIds.add(rid);
					// System.out.println("id add!:" + sysId);
				}

				router.setId(rid);
				topo.setMapLongStrId(rid, sysId);
				// System.out.println(rid);
				JSONArray neighbors = node.getJSONArray("neighbors");
				nSize = neighbors.length();

				for (int j = 0; j < nSize; j++) {
					JSONObject neighbor = neighbors.getJSONObject(j);
					linkId = neighbor.getInt("id");
					nSysId = neighbor.getString("nSysId");
					metric = neighbor.getInt("metric");

					if (linkId != 0 && nSysId != null) {
						// topo.setMapLinkIdByte(linkId);
						topo.setMapLidTraffic(linkId);
						link = new Link();
						link.setLinkId(linkId);
						link.setMyId(rid);
						link.setNeighborId(IPTranslator.calSysIdtoLong(nSysId));
						link.setMetric(metric);
						router.setLink(link);
					}
				}
				topo.setMapIdRouter(rid, router);
			}

			if (level == 1) {// 如果是1型网络，还要保存所有边界路由器的id，因为要全算
				topo.setBrIdList(brIds);
			}

			JSONArray reaches = jObject.getJSONArray("Reachability");

			if (reaches == null) {
				return null;
			}

			size = reaches.length();
			JSONObject reach = null;
			Reachability r1 = null;

			for (int i = 0; i < size; i++) {
				reach = reaches.getJSONObject(i);

				if (reach == null) {
					return null;
				}

				sysId = reach.getString("sysId");

				if (sysId == null) {
					return null;
				}

				metric = reach.getInt("metric");
				prefix = reach.getLong("prefix");

				rid = IPTranslator.calSysIdtoLong(sysId);

				if (level == 2) {//
					// 如果是l1型网络，只存视图stub类型的prefix——id映射，不存reachability，如果是2型都存
					if (brIds.contains(rid)) {// 如果这个路由器id在保存所有l1/l2的路由器id列表中
						r1 = new Reachability();
						r1.setSysId(rid);
						r1.setPrefix(prefix);
						r1.setMetric(metric);
						topo.setMapPrefixReach(prefix, r1);
					}
				}

				topo.setMapPrefixRouterId(prefix, rid);// 存stub
				// System.out.println("prefix:" +
				// IPTranslator.calLongToIp(prefix)
				// + " rid:" + rid);
			}

		} catch (IOException e) {
			e.printStackTrace();
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return topo;
	}

	public String writeResult(HashMap<Integer, TrafficLink> mapLidTlink,
			HashMap<Long, StatisticItem> allStatistics, int interval, long pid) {

		String path = "TrafficTopoResult_" + pid + ".json";
		int id = 0;
		FileWriter fw = null;
		PrintWriter pw = null;
		// 遍历hashmap实例代码：
		JSONObject jobj = new JSONObject();

		try {
			jobj.put("interval", interval);
			jobj.put("periodID", pid);

			// 链路流量数据写入文件
			JSONArray links = new JSONArray();
			JSONObject linkObj = null;
			Map.Entry<Integer, TrafficLink> linkEntry = null;
			Iterator<Entry<Integer, TrafficLink>> linkIter = mapLidTlink
					.entrySet().iterator();
			TrafficLink toAdd = null;
			HashMap<String, Long> mapProtocalBytes = null;

			while (linkIter.hasNext()) {// 遍历要加入的map
				linkEntry = linkIter.next();
				linkObj = new JSONObject();

				id = linkEntry.getKey();
				toAdd = linkEntry.getValue();

				if (id == 0 || toAdd == null) {
					continue;
				}

				linkObj.put("id", id);
				linkObj.put("total", toAdd.getTotal());
				mapProtocalBytes = toAdd.getProtocalBytes();

				if (mapProtocalBytes.size() == 0) {// 如果链路上没有任何流量流过，就不加protocal和bytes数组
					links.put(linkObj);
					continue;
				}

				/*
				 * 格式是： "protocal":["ftp","telnet","http","other"],
				 * "bytes":[111,222,333,444]
				 */
				linkObj.put("protocal", mapProtocalBytes.keySet());
				linkObj.put("bytes", mapProtocalBytes.values());

				links.put(linkObj);
			}

			jobj.put("links", links);

			// 将ip和前缀的统计信息写入文件
			JSONArray ipinfos = new JSONArray();
			JSONObject ipObj = null;
			StatisticItem item = null;
			Map.Entry<Long, StatisticItem> ipEntry = null;
			Iterator<Entry<Long, StatisticItem>> ipIter = allStatistics
					.entrySet().iterator();
			HashMap<String, Long> flowDetail = null;

			while (ipIter.hasNext()) {
				ipEntry = ipIter.next();
				item = ipEntry.getValue();

				ipObj = new JSONObject();

				ipObj.put("ip", item.getIp());
				ipObj.put("online", item.getOnline());
				ipObj.put("inflow", item.getInFlow());
				ipObj.put("outflow", item.getOutFlow());
				ipObj.put("prefix", item.getPrefix());

				flowDetail = item.getMapInFlow();

				if (flowDetail.size() > 0) {
					ipObj.put("inProtocal", flowDetail.keySet());
					ipObj.put("inBytes", flowDetail.values());
				}

				flowDetail = item.getMapOutFlow();

				if (flowDetail.size() > 0) {
					ipObj.put("outProtocal", flowDetail.keySet());
					ipObj.put("outBytes", flowDetail.values());
				}

				ipinfos.put(ipObj);
			}

			jobj.put("ipinfos", ipinfos);

			// 写入文件
			fw = new FileWriter(path);
			pw = new PrintWriter(fw);
			pw.write(jobj.toString());
			fw.close();
			pw.close();
		} catch (JSONException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return path;
	}

	// 20130506 modified by lili
	public String writeResult(HashMap<Integer, TrafficLink> mapLidTlink,
			int interval, long pid) {

		String path = "TrafficTopoResult_" + pid + ".json";
		FileWriter fw = null;
		PrintWriter pw = null;
		// 遍历hashmap实例代码：
		JSONObject jobj = new JSONObject();

		try {
			jobj.put("interval", interval);
			jobj.put("periodID", pid);

			// 链路流量数据写入文件
			JSONArray links = new JSONArray();
			JSONObject linkObj = null;
			Map.Entry<Integer, TrafficLink> linkEntry = null;
			Iterator<Entry<Integer, TrafficLink>> linkIter = mapLidTlink
					.entrySet().iterator();
			TrafficLink toAdd = null;
			int id = 0;
			HashMap<String, Long> mapProtocalBytes = null;

			while (linkIter.hasNext()) {// 遍历要加入的map
				linkEntry = linkIter.next();
				linkObj = new JSONObject();

				id = linkEntry.getKey();
				toAdd = linkEntry.getValue();

				if (id == 0 || toAdd == null) {
					continue;
				}

				linkObj.put("id", id);
				linkObj.put("total", toAdd.getTotal());
				mapProtocalBytes = toAdd.getProtocalBytes();

				if (mapProtocalBytes.size() == 0) {// 如果链路上没有任何流量流过，就不加protocal和bytes数组
					links.put(linkObj);
					continue;
				}

				/*
				 * 格式是： "protocal":["ftp","telnet","http","other"],
				 * "bytes":[111,222,333,444]
				 */
				linkObj.put("protocal", mapProtocalBytes.keySet());
				linkObj.put("bytes", mapProtocalBytes.values());

				links.put(linkObj);
			}

			jobj.put("links", links);

			// 写入文件
			fw = new FileWriter(path);
			pw = new PrintWriter(fw);
			pw.write(jobj.toString());
			fw.close();
			pw.close();
		} catch (JSONException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return path;
	}
}
