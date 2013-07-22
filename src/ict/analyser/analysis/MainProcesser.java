/** Filename: MainProcesser.java
 * Copyright: ICT (c) 2012-10-21
 * Description: 
 * Author: 25hours
 */
package ict.analyser.analysis;

import ict.analyser.config.ConfigData;
import ict.analyser.flow.TrafficLink;
import ict.analyser.isistopo.IsisTopo;
import ict.analyser.netflow.Netflow;
import ict.analyser.ospftopo.OspfTopo;
import ict.analyser.receiver.ConfigReceiver;
import ict.analyser.receiver.FlowReceiver;
import ict.analyser.receiver.QueryReceiver;
import ict.analyser.receiver.TopoReceiver;
import ict.analyser.tools.FileProcesser;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Timer;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

//import ict.analyser.tools.FileProcesser;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-21
 */
public class MainProcesser {

	static long pid = 0; // 当前所处的周期标识

	static int topN = 50;// topN

	static int pidIndex = 1;// 周期索引

	static int interval = 15;// 配置文件中获得的计算周期单位:min

	static int divideCount = 3;// 将所有的netflow报文分成多少份，决定生成多少个线程进行路径分析

	static int delay = 20 * 1000;// 提前接收拓扑的时间，流量接收是时间出发的，从第二周期起，接收到拓扑后的delay秒发送流量请求

	private Timer timer = null;// 定时器类

	private Lock configLock = null;// 为configData数据加锁

	private String protocol = null;// 分析的协议类型‘ospf’ 或 ‘isis’

	private IsisTopo isisTopo = null;// Isis拓扑

	private OspfTopo ospfTopo = null;// ospf 拓扑

	private ConfigData configData = null;// 保存配置信息的对象

	private IpStatistics ipStatistics = null;// ip在线时长统计，ip和前缀对应流量统计

	private Thread ipStatisticThread = null;// 封装ip在线时长统计的类的线程

	private FlowReceiver flowReceiver = null;// flow接收类对象

	private TopoReceiver topoReceiver = null;// 拓扑接收类对象

	private ResultSender resultSender = null;// 结果发送类对象

	private Condition configCondition = null;// 锁相关：设置等待唤醒，相当于wait/notify

	// rivate ArrayList<Flow> topNFlows = null;// top n条流路径

	private RouteAnalyser routeAnalyser = null;// flow路径分析的主要类对象

	private QueryReceiver queryReceiver = null;// 接收流查询的线程

	private FileProcesser fileProcesser = null;// 文件处理类对象

	private ConfigReceiver configReceiver = null;// 配置接收类对象

	private ArrayList<Netflow> netflows = null;// flow接收模块分析并聚合后得到的报文对象列表

	// private HashMap<Integer, Long> mapLinkIdBytes = null;// link id——bytes 映射
	// 保存发送给综合分析板卡的信息，链路id和对应链路上流量大小
	private HashMap<Integer, TrafficLink> mapLidTlink = null;// link id ——

	public MainProcesser() {
		initMaterials();// 初始化类变量
	}

	/**
	 * 初始化整个分析流程所需要的类变量，包含将netflow报文解析后的输出和topo文件解析后的输出复制过来
	 */
	public void initMaterials() {
		this.timer = new Timer();// 初始化一个定时器类
		this.configLock = new ReentrantLock();// 初始化锁
		this.queryReceiver = new QueryReceiver();// 初始化流查询线程
		this.configCondition = this.configLock.newCondition();// 加锁解锁条件变量
		this.configReceiver = new ConfigReceiver();// 配置接收模块实例化
		this.ipStatistics = new IpStatistics();
		this.flowReceiver = new FlowReceiver();// flow接收模块实例化
		this.routeAnalyser = new RouteAnalyser();// 路径分析类对象初始化
		this.topoReceiver = new TopoReceiver(this);// 拓扑接收模块实例化
		this.fileProcesser = new FileProcesser();// 将路径分析结果写入文件的类对象
		// this.mapLinkIdBytes = new HashMap<Integer, Long>();// 链路id——流量大小 映射
		// this.topNFlows = new ArrayList<Flow>();// top n条流路径
		this.mapLidTlink = new HashMap<Integer, TrafficLink>();// 链路id——业务流量对象
		this.configReceiver.start();// 开始配置接收
		this.topoReceiver.start();// 启动拓扑接收模块开始监听socket
		this.queryReceiver.start();
	}

	/**
	 * 由Main类调用，真个程序的入口函数
	 */
	public void startWorking() {
		while (true) {
			process();// 主处理函数
		}
	}

	/**
	 * 每个周期都要重置的变量
	 */
	public void resetMaterials() {
		// 重置变量
		// this.topNFlows.clear();
		// this.mapLinkIdBytes.clear();
		this.mapLidTlink.clear();
		this.flowReceiver.clearFlows();// 20130226加，分析完路径清空流量
		this.ipStatistics.clearStatistics();// 分析完清空ip在线时长统计数据
	}

	/**
	 * 主分析函数，每周期执行一次
	 */
	public void process() {

		resetMaterials();// 重置变量

		configLock.lock(); // 加锁配置信息对象
		configData = this.configReceiver.getConfigData();// 获得配置信息对象
		configCondition.signal();// 通知在这个condition上锁住的变量解锁
		configLock.unlock();// 解锁配置信息对象

		if (configData == null) {// 如果配置信息为空，报错
			System.out.println("configData is null!");
			return;
		}

		if (pidIndex == 1) {// 如果是第一个周期
			boolean syn = this.flowReceiver.sendStartSignal();// 第一个周期解析完配置文件之后向流量汇集设备发送开始接收流量的信号

			if (!syn) { // 如果设备没有正确打开，本周期不分析
				// 汇报？？或可以设个定时器，程序等待一个周期再return，进行下一个大循环
				int wait = this.configData.getInterval() * 60 * 1000;

				try {// 等一个周期再返回
					Thread.sleep(wait);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				return;
			}
		}

		this.topoReceiver.getTopoSignal();// 开始接收拓扑的信号
		int advance = this.configData.getInAdvance();

		if (delay != advance * 1000) {
			delay = advance == 0 ? 20 * 1000 : advance * 1000;
		}

		if (pidIndex == 1) {// 如果 是第一周期
			System.out.println("first period! ");
			this.timer.schedule(flowReceiver, 0);// 马上开始netflow接收，说明：第一个周期所能分析的流量数量是根据配置文件和第一份拓扑文件接收的时间间隔而定的，如果两者同时接收，那么流量可能为0，进入下一周期。
		}

		int newInterval = this.configData.getInterval();// 以分钟为单位，得到分析周期

		if (newInterval != interval) {// 捕获计算时间间隔的改变
			System.out.println("interval changed!");
			interval = newInterval;
		}

		if (pidIndex > 1) { // 从第二个周期开始在拓扑文件接收后delay秒接收流量
			flowReceiver = new FlowReceiver();
			timer.schedule(flowReceiver, delay);
		}

		this.protocol = this.configData.getProtocol();// 得到协议类型

		if (this.protocol == null) {// 合法性检验
			System.out.println("protocol field of config file is null!");
			pidIndex++;
			return;
		}

		boolean isSuccess = false;

		if (this.protocol.equalsIgnoreCase("ospf")) {
			isSuccess = ospfProcess();
		} else {
			isSuccess = isisProcess();
		}

		// if (netflows != null) {
		// System.out.println("total flow is :" + this.netflows.size());
		// }

		// this.flowReceiver.closeConnect();
		// this.mapLinkIdBytes = this.routeAnalyser.getMapLinkIdBytes();//
		// 得到路径分析后的结果链路id——byte映射
		this.mapLidTlink = this.routeAnalyser.getMapLidTlink();// 得到路径分析后的结果链路id—业务流量映射
		// 如果拓扑为空，只发送pid
		if (this.mapLidTlink == null || this.mapLidTlink.size() == 0) {
			pidIndex++;

			this.resultSender = new ResultSender( // 分析失败，发送1到综合分析板卡
					this.configData.getGlobalAnalysisPort(),
					this.configData.getGlobalAnalysisIP());
			this.resultSender.setPid(pid);
			new Thread(resultSender).start();// 发送给综合分析板卡

			return;
		}

		String filePath = null;

		if (!isSuccess) { // 流量为空20130506 modified by lili
			pidIndex++;
			filePath = this.fileProcesser.writeResult(this.mapLidTlink,
					this.configData.getInterval(), pid);

			if (filePath != null && this.configData != null) {// 流量为空
																// 发送全部拓扑给综合分析板卡20130506
																// modified by
																// lili
				this.resultSender = new ResultSender(
						this.configData.getGlobalAnalysisPort(),
						this.configData.getGlobalAnalysisIP(), filePath);
				new Thread(resultSender).start();// 发送给综合分析板卡
			}

			return;
		}

		try {
			this.ipStatisticThread.join();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		filePath = this.fileProcesser.writeResult(this.mapLidTlink,
				this.ipStatistics.getAllItems(), this.configData.getInterval(),
				pid);// 调用fileProcesser来将得到的路径写入文件中,返回文件路径

		// System.out.println("global analysis ip:"
		// + this.configData.getGlobalAnalysisIP() + "   port:"
		// + this.configData.getGlobalAnalysisPort());

		if (filePath != null && this.configData != null) {
			this.resultSender = new ResultSender(
					this.configData.getGlobalAnalysisPort(),
					this.configData.getGlobalAnalysisIP(), filePath);
			new Thread(resultSender).start();// 发送给综合分析板卡
		}

		pidIndex++;// 周期索引增加
	}

	public boolean isisProcess() {
		this.isisTopo = this.topoReceiver.getIsisTopo();// 得到分析后的isis拓扑对象

		if (this.isisTopo == null) {// 如果拓扑对象没得到，返回
			return false;
		}

		// System.out.println("isis topo got!");

		this.routeAnalyser.setTopo(this.isisTopo);// 为路径分析设置topo

		this.routeAnalyser.setMapLidTlink(this.isisTopo.getMapLidTlink());
		pid = this.isisTopo.getPeriodId();
		// System.out.println("pid:" + pid);

		if (pidIndex > 1) {// 第二周期以后要开始提前计算路径了
			System.out.println("isis precalculating!");
			routeAnalyser.isisPreCalculate();
		}

		// System.out.println("")
		this.netflows = this.flowReceiver.getAllFlows(pidIndex);// 得到全部flow

		if (this.netflows == null || this.netflows.size() == 0) {// 如果flow文件没得到，返回
			System.out.println("main processer netflow null!");
			return false;
		}

		System.out.println(this.netflows.size() + "flows got!");
		// 开始统计
		this.ipStatistics.setFlows(this.netflows);
		this.ipStatisticThread = new Thread(this.ipStatistics);
		this.ipStatisticThread.start();
		// 开始分析flow路径

		this.routeAnalyser.setNetflows(this.netflows);// 将flow给routeAnalyser

		this.routeAnalyser.isisRouteCalculate(pid);// 计算flow路径

		return true;
	}

	public boolean ospfProcess() {

		this.ospfTopo = this.topoReceiver.getOspfTopo();// 得到分析后的ospf拓扑对象

		if (this.ospfTopo == null) {// 如果拓扑对象没得到，返回
			return false;
		}

		this.routeAnalyser.setTopo(this.ospfTopo);

		this.routeAnalyser.setMapLidTlink(this.ospfTopo.getMapLidTlink());

		pid = this.ospfTopo.getPeriodId();

		if (pidIndex > 1) {// 第二周期以后要开始提前计算路径了
			routeAnalyser.ospfPreCalculate();
		}

		this.netflows = this.flowReceiver.getAllFlows(pidIndex);// 得到全部flow

		if (this.netflows == null || this.netflows.size() == 0) {// 如果flow文件没得到，返回
			return false;
		}

		System.out.println(this.netflows.size() + "flows got!");
		// // 开始统计
		this.ipStatistics.setAS(this.ospfTopo.getAsNumber());
		this.ipStatistics.setFlows(this.netflows);
		this.ipStatistics.setNeighborAsIps(this.ospfTopo
				.getNeighborIpsOfInterLink());
		this.ipStatisticThread = new Thread(this.ipStatistics);
		this.ipStatisticThread.start();
		// 开始分析flow路径
		this.routeAnalyser.setNetflows(this.netflows);// 将flow给routeAnalyser
		this.routeAnalyser.ospfRouteCalculate(pid);// 计算flow路径

		return true;
	}

	/**
	 * @return Returns the configData.
	 */
	public ConfigData getConfigData() {

		configLock.lock();
		try {
			if (this.configData == null) {
				configCondition.await();
			}
			return configData;
		} catch (InterruptedException e) {
			e.printStackTrace();
			return null;
		} finally {
			configLock.unlock();
		}
	}

	/**
	 * @return Returns the netflows.
	 */
	public ArrayList<Netflow> getNetflows() {
		return netflows;
	}

	/**
	 * @return Returns the protocol.
	 */
	public String getProtocol() {
		return protocol;
	}

}
