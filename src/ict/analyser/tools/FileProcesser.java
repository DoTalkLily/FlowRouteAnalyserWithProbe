/* 
 * Filename: FileProcesser.java
 * Description: Parse JSON files
 * @author: Liu Xiang
 * @version 1.0, 2012-10-14
 */

package ict.analyser.tools;

import ict.analyser.config.ConfigData;
import ict.analyser.flow.TrafficLink;
import ict.analyser.isistopo.IsisRouter;
import ict.analyser.isistopo.IsisTopo;
import ict.analyser.isistopo.Reachability;
import ict.analyser.ospftopo.AsExternalLSA;
import ict.analyser.ospftopo.BgpItem;
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
import java.util.logging.Logger;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class FileProcesser {
	private long pid = 0;
	private boolean isOuterChanged = true;// 标记本周期bgp信息是否发生改变
	private boolean isTopoChanged = true;// 标记本周期拓扑是否发生改变
	private Logger logger = Logger.getLogger(FileProcesser.class.getName());// 注册一个logger

	public static ConfigData readConfigData(String filePath) {
		String topoString = "";
		JSONObject jObject = null;
		ConfigData configData = new ConfigData();

		try {
			BufferedReader br = new BufferedReader(new FileReader(filePath));
			String r = br.readLine();

			while (r != null) {
				topoString += r;
				r = br.readLine();
			}
			br.close();

			jObject = new JSONObject(topoString);
			int topN = jObject.getInt("topN");
			int interval = jObject.getInt("interval");
			int inAdvance = jObject.getInt("inAdvance");
			int samplingRate = jObject.getInt("samplingRate");
			int globalAnalysisPort = jObject.getInt("globalAnalysisPort");
			String protocal = jObject.getString("protocol");
			String globalAnalysisIP = jObject.getString("globalAnalysisIP");
			JSONArray portArr = jObject.getJSONArray("observePorts");
			int size = portArr.length();

			for (int i = 0; i < size; i++) {
			}

			if (protocal != null && interval > 1 && globalAnalysisIP != null
					&& globalAnalysisPort > 0 && inAdvance > 0 && topN > 0
					&& samplingRate > 0) {
				configData.setTopN(topN);
				configData.setInterval(interval);
				configData.setProtocol(protocal);
				configData.setInAdvance(inAdvance);
				configData.setSamplingRate(samplingRate);
				configData.setGlobalAnalysisIP(globalAnalysisIP);
				configData.setGlobalAnalysisPort(globalAnalysisPort);
			}
		} catch (JSONException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return configData;
	}

	// parameters:
	// The location of JSON file
	public OspfTopo readOspfTopo(String filePath) {
		this.isOuterChanged = true;// 默认bgp信息发生改变
		this.isTopoChanged = true;// 默认拓扑发生改变

		String topoString = "";
		JSONObject jObject = null;

		try {
			// 将topo文件内容读入赋值给字符串
			BufferedReader br = new BufferedReader(new FileReader(filePath));
			String line = br.readLine();

			while (line != null) {
				topoString += line;
				line = br.readLine();
			}

			br.close();
			jObject = new JSONObject(topoString);
			// pid
			this.pid = jObject.getLong("pid");
			OspfTopo topo = null;
			// 解析开始
			if (!jObject.has("Topo")) {// 如果拓扑没发生变化——通过判断是否有“topo”key来判断本周期拓扑数据是否发生变化
				this.isTopoChanged = false;
				logger.info("topo not changed ! pid:" + pid);
			} else {
				topo = processTopo(jObject);

				// 如果拓扑解析错误，标记拓扑没有改变，用原来的拓扑
				if (topo == null) {
					logError("topo process failed!");
					return null;
				}
			}

			// bgp信息和external lsa信息，两者同步变化
			HashMap<Long, BgpItem> mapPrefixBgpItem = null;
			HashMap<Long, AsExternalLSA> mapPrefixLsa5 = null;

			if (!jObject.has("OuterInfo")) {
				this.isOuterChanged = false;
				logger.info("outer info not changed!pid:" + pid);
			} else {
				JSONObject outerInfo = jObject.getJSONObject("OuterInfo");

				if (!outerInfo.has("BGP") || !outerInfo.has("ExternalLsa")) {
					logError("bgp info or lsa5 info is null!pid:" + pid);
					return null;
				}

				mapPrefixBgpItem = processBgp(outerInfo.getJSONArray("BGP"));
				mapPrefixLsa5 = processExternalLsa(outerInfo
						.getJSONArray("ExternalLsa"));

				// 只有在json解析出错的情况下才会返回空,标记它为改变
				if (mapPrefixBgpItem == null || mapPrefixLsa5 == null) {
					logError("outer info process failed or one attribute is null");
					return null;
				}

				// 如果
				if (mapPrefixBgpItem.size() == 0 && mapPrefixLsa5.size() == 0) {
					logError("bgp info and lsa5 info are null which should be given");
					return null;
				}

				// 如果拓扑信息没改变，即文件中没有“Topo”一块，这里topo是没初始化的；用解析的两个结构初始化，因为参数为空的构造函数要多初始化多个无用变量
				if (topo == null) {
					topo = new OspfTopo(false);
				}
				topo.setMapPrefixBgpItem(mapPrefixBgpItem);
				topo.setMapPrefixExternalLsa(mapPrefixLsa5);
			}
			return topo;
		} catch (IOException e) {
			logError(e.toString());
		} catch (JSONException e) {
			logError(e.toString());
		}
		return null;
	}

	private void logError(String msg) {
		logger.warning(msg);
		this.isTopoChanged = false;
		this.isOuterChanged = false;
	}

	public OspfTopo processTopo(JSONObject jObject) {
		long ip = 0;
		long rid = 0;
		int size = 0;
		int linkId = 0;
		int metric = 0;
		long prefix = 0;
		int asNumber = 0;
		long nAsNumber = 0;
		int neighborSize = 0;
		Link link = null;
		String area = null;
		String mask = null;
		String routerId = null;
		String nRouterId = null;
		OspfRouter router = null;
		String interfaceIP = null;
		OspfTopo topo = new OspfTopo(true);
		// pid
		topo.setPeriodId(this.pid);
		try {
			// asNumber
			asNumber = jObject.getInt("asNumber");
			topo.setAsNumber(asNumber); // asNumber
			// topo
			JSONObject topoObj = jObject.getJSONObject("Topo");
			// nodes
			JSONArray nodes = topoObj.getJSONArray("nodes");
			size = nodes.length();

			for (int i = 0; i < size; i++) {
				router = new OspfRouter();
				JSONObject node = nodes.getJSONObject(i);
				routerId = node.getString("routerId");
				rid = IPTranslator.calIPtoLong(routerId);
				router.setRouterId(rid); // routerId
				JSONArray neighbors = node.getJSONArray("neighbors");
				neighborSize = neighbors.length();

				for (int j = 0; j < neighborSize; j++) {
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
						topo.setMapLidTraffic(linkId);
						topo.setMapIpRouterid(ip, rid);// 添加到保存as内路由器ip——rid映射中
					}
				}
				topo.setRidRouter(rid, router);
			}
			// stubs
			JSONArray stubs = topoObj.getJSONArray("stubs");
			size = stubs.length();

			for (int i = 0; i < size; i++) {
				JSONObject stub = stubs.getJSONObject(i);
				mask = stub.getString("mask");
				prefix = stub.getLong("prefix");
				routerId = stub.getString("routerId");

				if (routerId != null && prefix != 0 && mask != null) {
					topo.setMapPrefixRouterId(prefix,
							IPTranslator.calIPtoLong(routerId));
				}
			}
			// asbr
			JSONArray asbrs = topoObj.getJSONArray("InterLink");
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
				mask = asbr.getString("mask");
				linkId = asbr.getInt("linkId");
				metric = asbr.getInt("metric");
				nAsNumber = asbr.getInt("nAsNumber");
				routerId = asbr.getString("routerId");
				ipstr = asbr.getString("nInterfaceIP");
				nRouterId = asbr.getString("nRouterId");
				interfaceIP = asbr.getString("interfaceIP");

				if (linkId != 0 && routerId != null && interfaceIP != null
						&& mask != null && nRouterId != null && nAsNumber != 0
						&& input >= 0) {

					topo.setMapLidTraffic(linkId);// linkId
					interLink.setLinkId(linkId);
					// routerId
					rid = IPTranslator.calIPtoLong(routerId);// 这里的routerId是邻居as的asbr的rid
					interLink.setMyBrId(rid);
					// interfaceIp
					ip = IPTranslator.calIPtoLong(interfaceIP);// 这里的interfaceip是邻居as的asbr的接口ip
					interLink.setMyInterIp(ip);
					// mask
					masklong = IPTranslator.calIPtoLong(mask);
					interLink.setMask(masklong);
					// nRouterId
					rid = IPTranslator.calIPtoLong(nRouterId);// 这里“nRouterId”是本as的asbr的id
					interLink.setNeighborBrId(rid);
					// nInterfaceIP
					ip = IPTranslator.calIPtoLong(ipstr);// 这里的“nInterfaceIP”是邻居as的asbr的接口ip
					interLink.setNeighborBrIp(ip);
					// nAsNumber
					interLink.setNeighborAS(nAsNumber);
					// metric
					interLink.setMetric(metric);
					// input
					interLink.setInput(input);

					topo.setMapIpRouterid(interLink.getMyInterIp(),
							interLink.getMyBrId());// 域内as内的所有ip——rid映射
					topo.setInterAsLinks(interLink.getNeighborBrIp(), interLink);// 设置边界链路
					topo.setMapASBRIpLinkId(interLink.getMyInterIp(), linkId);// 边界路由器ip——链路ip映射，两端的ip都存
					topo.setMapASBRIpLinkId(interLink.getNeighborBrIp(), linkId);
				}
			}
			return topo;
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return null;
	}

	public HashMap<Long, BgpItem> processBgp(JSONArray bgpObj) {
		int len = 0;
		int origin = 0;
		int metric = 0;
		int weight = 0;
		String prefix = null;
		String nextHop = null;
		int localPreference = 0;
		long prefixLong = 0l;
		ArrayList<Integer> asPath = null;
		BgpItem bgpItem = null;
		HashMap<Long, BgpItem> mapPrefixBgp = new HashMap<Long, BgpItem>();

		try {
			// BGP
			int asSize = 0;
			int itemSize = bgpObj.length();
			BgpItem item = null;
			JSONObject node = null;
			JSONArray pathArr = null;

			for (int i = 0; i < itemSize; i++) {
				node = bgpObj.getJSONObject(i);
				nextHop = node.getString("nexthop");

				if (nextHop.equals("0.0.0.0")) {// 如果是as内的路由 则不存储
					continue;
				}

				prefix = node.getString("prefix");
				len = node.getInt("length");
				weight = node.getInt("weight");
				origin = node.getInt("origin");
				localPreference = node.getInt("localPreference");
				metric = node.getInt("med");
				pathArr = node.getJSONArray("aspath");
				asSize = pathArr.length();

				if (asSize > 0) {
					asPath = new ArrayList<Integer>();

					for (int j = 0; j < asSize; j++) {
						asPath.add(pathArr.getInt(j));
					}
				}

				if (prefix != null && len >= 0 && nextHop != null
						&& origin >= 0 && weight >= 0 && localPreference >= 0
						&& metric >= 0 && asSize > 0) {
					item = new BgpItem();
					item.setLength(len);
					item.setWeight(weight);
					item.setOrigin(origin);
					item.setMetric(metric);
					item.setAsPath(asPath);
					item.setLocalProference(localPreference);
					prefixLong = IPTranslator.calIPtoLong(prefix);
					item.setPrefix(prefixLong);
					item.setNextHop(IPTranslator.calIPtoLong(nextHop));

					bgpItem = mapPrefixBgp.get(prefixLong);

					if (bgpItem == null) {
						mapPrefixBgp.put(prefixLong, item);
					} else {
						mapPrefixBgp.put(prefixLong,
								chooseBestRoot(item, bgpItem));// 选最优的插入
					}
				}
			}
			return mapPrefixBgp;
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return null;
	}

	private HashMap<Long, AsExternalLSA> processExternalLsa(
			JSONArray externalLsa) {

		int metric;
		int externalType;
		long prefix;
		String mask;
		String nexthop;
		String routerId;
		String prefixStr;
		AsExternalLSA lsa;
		HashMap<Long, AsExternalLSA> mapPrefixLsa = new HashMap<Long, AsExternalLSA>();

		int size = externalLsa.length();
		try {
			for (int j = 0; j < size; j++) {
				JSONObject asExternalObj;
				asExternalObj = externalLsa.getJSONObject(j);

				lsa = new AsExternalLSA();
				metric = asExternalObj.getInt("metric");
				mask = asExternalObj.getString("networkMask");
				routerId = asExternalObj.getString("advRouter");
				prefixStr = asExternalObj.getString("linkStateId");
				externalType = asExternalObj.getInt("externalType");
				nexthop = asExternalObj.getString("forwardingAddress");

				if (routerId != null && prefixStr != null && mask != null
						&& externalType != 0 && nexthop != null) {
					lsa.setAdvRouter(IPTranslator.calIPtoLong(routerId)); // advRouter
					prefix = IPTranslator.calIPtoLong(prefixStr);
					lsa.setLinkStateId(prefix); // linkStateId
					lsa.setNetworkMask(IPTranslator.calIPtoLong(mask)); // networkMask
					lsa.setExternalType(externalType); // externalType
					lsa.setMetric(metric); // metric
					lsa.setForwardingAddress(IPTranslator.calIPtoLong(nexthop)); // forwardingAddress
					mapPrefixLsa.put(prefix, lsa);
				}
			}
			return mapPrefixLsa;
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return null;
	}

	/*
	 * 如果两个item宣告了到达同一个prefix 根据各种规则选一个最优的
	 */
	private BgpItem chooseBestRoot(BgpItem item1, BgpItem item2) {
		if (item1.getWeight() != item2.getWeight()) { // weight
			return (item1.getWeight() > item2.getWeight()) ? item1 : item2;// 越大越好
		}

		if (item1.getLocalProference() != item2.getLocalProference()) { // localpreference
			return (item1.getLocalProference() > item2.getLocalProference()) ? item1
					: item2;// 越大越好
		}

		int size1 = item1.getAsPath().size();
		int size2 = item2.getAsPath().size();

		if (size1 != size2) {// as path size
			return (size1 > size2) ? item2 : item1;// 越小越好
		}

		if (item1.getOrigin() != item2.getOrigin()) {// origin
			return (item1.getOrigin() > item2.getOrigin()) ? item2 : item1;// 越小越好
		}

		if (item1.getMed() != item2.getMed()) {// med
			return (item1.getMed() > item2.getMed()) ? item2 : item1;// 越小越好
		}

		// 这里有待扩展…… 13条中7-13条，扩展前，还不能确定唯一一条 就返回第一条
		return item1;
	}

	public IsisTopo readIsisTopo(String filePath) {
		this.isTopoChanged = true;

		long rid = 0;
		int level = 0;
		int metric = 0;
		int linkId = 0;
		int sysType = 0;
		long prefix = 0;
		Link link = null;
		String sysId = null;
		String nSysId = null;
		String topoString = "";
		IsisRouter router = null;
		JSONObject jObject = null;
		IsisTopo topo = new IsisTopo();
		ArrayList<Long> brIds = new ArrayList<Long>();

		try {
			BufferedReader br = new BufferedReader(new FileReader(filePath));
			String line = br.readLine();

			while (line != null) {
				topoString += line;
				line = br.readLine();
			}

			br.close();
			jObject = new JSONObject(topoString);

			// 解析开始
			if (!jObject.has("Topo")) {// 如果拓扑没发生变化——通过判断是否有“topo”key来判断本周期拓扑数据是否发生变化
				this.pid = jObject.getLong("pid");
				this.isTopoChanged = false;
				logger.info("pid:" + pid);
				return null;
			}

			level = jObject.getInt("level");

			if (level != 2 && level != 1) {
				return null;
			}

			String areaId = jObject.getString("areaId");

			if (areaId == null) {
				return null;
			}

			JSONObject jTopo = jObject.getJSONObject("Topo");
			this.pid = jTopo.getLong("pid");
			topo.setPeriodId(this.pid);
			topo.setNetworkType(level);
			logger.info("pid : " + pid);

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
			HashMap<Long, StatisticItem> allStatistics, int interval) {

		String path = "TrafficTopoResult_" + this.pid + ".json";
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
			int interval) {

		String path = "TrafficTopoResult_" + this.pid + ".json";
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

	/**
	 * @return Returns the isTopoChanged.
	 */
	public boolean isTopoChanged() {
		return isTopoChanged;
	}

	/**
	 * @return Returns the isBgpChanged.
	 */
	public boolean isOuterInfoChanged() {
		return isOuterChanged;
	}

	/**
	 * @return Returns the pid.
	 */
	public long getPid() {
		return pid;
	}
}
