/** Filename: MainProcesser.java
 * Copyright: ICT (c) 2012-10-21
 * Description: 
 * Author: 25hours
 */
package ict.analyser.analysis;

import ict.analyser.common.Constant;
import ict.analyser.communication.ConfigReceiver;
import ict.analyser.communication.FlowReceiver;
import ict.analyser.communication.QueryReceiver;
import ict.analyser.communication.ResultSender;
import ict.analyser.communication.TopoReceiver;
import ict.analyser.config.ConfigData;
import ict.analyser.flow.TrafficLink;
import ict.analyser.isistopo.IsisTopo;
import ict.analyser.netflow.Netflow;
import ict.analyser.ospftopo.OspfTopo;
import ict.analyser.tools.FileProcesser;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Timer;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

//import ict.analyser.tools.FileProcesser;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-21
 */
public class MainProcesser {
	static long PID = 0; // 当前所处的周期标识
	static int TOPN = 50;// topN
	static int PID_INDEX = 1;// 周期索引
	static int INTERVAL = 10;// 配置文件中获得的计算周期单位:min
	static int DIVIDE_COUNT = 5;// 将所有的netflow报文分成多少份，决定生成多少个线程进行路径分析
	static int DELAY = 10 * 1000;// 提前接收拓扑的时间，流量接收是时间出发的，从第二周期起，接收到拓扑后的delay秒发送流量请求
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
	private RouteAnalyser routeAnalyser = null;// flow路径分析的主要类对象
	private QueryReceiver queryReceiver = null;// 接收流查询的线程
	private ArrayList<Netflow> netflows = null;// flow接收模块分析并聚合后得到的报文对象列表
	private ConfigReceiver configReceiver = null;// 配置接收类对象
	private static boolean deviceOpend = true;
	private Logger logger = Logger.getLogger(MainProcesser.class.getName());// 注册一个logger

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
		this.ipStatistics = new IpStatistics();// 统计各类信息线程
		this.flowReceiver = new FlowReceiver();// flow接收模块实例化
		this.routeAnalyser = new RouteAnalyser();// 路径分析类对象初始化
		this.queryReceiver = new QueryReceiver();// 初始化流查询线程
		this.topoReceiver = new TopoReceiver(this);// 拓扑接收模块实例化
		this.configReceiver = new ConfigReceiver();// 配置接收模块实例化
		this.configCondition = this.configLock.newCondition();// 加锁解锁条件变量
		this.mapLidTlink = new HashMap<Integer, TrafficLink>();// 链路id——业务流量对象

		this.configReceiver.start();// 开始配置接收
		this.topoReceiver.start();// 启动拓扑接收模块开始监听socket
		this.queryReceiver.start();// 查询请求接受
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
		this.flowReceiver.clearFlows();// 20130226加，分析完路径清空流量
		this.ipStatistics.clearStatistics();// 分析完清空ip在线时长统计数据
	}

	/**
	 * 主分析函数，每周期执行一次
	 */
	public void process() {
		resetMaterials();// 重置变量
		this.configData = getConfig();// 从ConfigReceiver对象中获得配置信息对象

		if (this.configData == null) {// 如果配置信息为空，报错
			logger.warning("configData is null!");
			return;
		}

		int advance = this.configData.getInAdvance();
		this.protocol = this.configData.getProtocol();// 得到协议类型

		if (this.protocol == null) {// 合法性检验
			logger.warning("protocol field of config file is null!");
			return;
		}

		if (DELAY != advance * 1000) {
			DELAY = advance == 0 ? 10 * 1000 : advance * 1000;
		}

		if (PID_INDEX == 1 || !deviceOpend) {// 如果是第一个周期或者硬件段代码没开启成功，再发送开启信号
			deviceOpend = this.flowReceiver.sendStartSignal();// 第一个周期解析完配置文件之后向流量汇集设备发送开始接收流量的信号
		}

		if (!deviceOpend) { // 如果设备没开启成功，则等收到本周起拓扑后，经过n秒后向综合分析板卡直接发送拓扑，进入下一次循环
			processDeviceFault();
			return;
		}

		int newInterval = this.configData.getInterval();// 以分钟为单位，得到分析周期

		if (newInterval != INTERVAL) {// 捕获计算时间间隔的改变
			logger.info("interval changed!");
			INTERVAL = newInterval;
		}

		this.routeAnalyser.setMapPortProtocal(this.configData
				.getMapPortProtocal()); // 将端口号——协议名映射赋值给分析线程

		this.topoReceiver.getTopoSignal();// 开始接收拓扑的信号

		this.flowReceiver = null;// 显式释放对象 这里让第一个周期和之后的周期处理方式相同，都要预先计算路径再铺流量
		this.flowReceiver = new FlowReceiver();// 不能重复schedule同一个对象，所以每周期都新建一个对象，这里用周期执行是不可靠的，由于周期可能会变化
		this.timer.schedule(flowReceiver, DELAY);

		int message = -1;

		if (this.protocol.equalsIgnoreCase("ospf")) {
			message = ospfProcess();
		} else {
			message = isisProcess();
		}

		System.out.println("ospf process done...");

		if (message == Constant.TOPO_NOT_RECEIVED) {// 如果拓扑错误，只发送pid给综合分析
			PID_INDEX++;
			reportPidToGlobal();
			return;
		}

		if (message == Constant.FLOW_NOT_RECEIVED) {// 如果流量为空，只发送拓扑结构给综合分析
			PID_INDEX++;
			reportTopoToGlobal();
			return;
		}

		// 得到路径分析后的结果链路id——byte映射
		this.mapLidTlink = this.routeAnalyser.getMapLidTlink();// 得到路径分析后的结果链路id—业务流量映射

		if (this.mapLidTlink == null || this.mapLidTlink.size() == 0) {// 如果拓扑对象不为空，但是拓扑上没有链路信息，发送pid给综合分析
			PID_INDEX++;// 周期索引增加
			reportPidToGlobal();// 如果拓扑为空，发送pid到综合分析板卡
			return;
		}

		// 否则 ，等待统计分析线程结束后，将全部结构发送给综合分析
		try {
			this.ipStatisticThread.join();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		reportAllStaticsToGlobal();// 分析完成，流程完全正确，发送全部数据给综合分析板卡
		PID_INDEX++;// 周期索引增加
	}

	public int isisProcess() {
		this.isisTopo = this.topoReceiver.getIsisTopo();// 得到分析后的isis拓扑对象

		if (this.isisTopo == null) {// 如果拓扑对象没得到，返回
			logger.warning("Isis  topo is null !");
			return Constant.TOPO_NOT_RECEIVED;
		}

		// PID = this.isisTopo.getPeriodId();
		this.routeAnalyser.setTopo(this.isisTopo);// 设置新的拓扑对象给分析线程

		if (PID_INDEX == 1) { // 第一个周期提前计算路径
			routeAnalyser.isisPreCalculate();
		} else if (PID_INDEX > 1 && this.topoReceiver.isTopoChanged()) {// 第二周期以后如果拓扑发生改变才需要提前计算路径
			routeAnalyser.isisPreCalculate();
		}

		this.netflows = this.flowReceiver.getAllFlows(PID_INDEX);// 得到全部flow

		if (this.netflows == null || this.netflows.size() == 0) {// 如果flow文件没得到，返回
			logger.warning("no flow got in pid:" + PID);
			return Constant.FLOW_NOT_RECEIVED;
		}

		// 开始统计
		this.ipStatistics.setFlows(this.netflows);
		this.ipStatisticThread = new Thread(this.ipStatistics);
		this.ipStatisticThread.start();
		// 开始分析flow路径
		this.routeAnalyser.setNetflows(this.netflows);// 将flow给routeAnalyser
		this.routeAnalyser.isisRouteCalculate(PID);// 计算flow路径

		return Constant.FLOW_ANALYSIS_SUCCESS;
	}

	public int ospfProcess() {
		this.ospfTopo = this.topoReceiver.getOspfTopo();// 得到分析后的ospf拓扑对象

		if (this.ospfTopo == null) {// 如果拓扑对象没得到，返回
			logger.warning("Ospf topo is null !");
			return Constant.TOPO_NOT_RECEIVED;
		}

		// PID = this.ospfTopo.getPeriodId();// 获得周期
		this.routeAnalyser.setTopo(this.ospfTopo);// 拓扑对象给分析线程

		if (PID_INDEX == 1) { // 第一个周期提前计算路径
			routeAnalyser.ospfPreCalculate();
		} else if (PID_INDEX > 1 && this.topoReceiver.isTopoChanged()) {// 第二周期以后如果拓扑发生改变才需要提前计算路径
			routeAnalyser.ospfPreCalculate();
		}

		this.netflows = this.flowReceiver.getAllFlows(PID_INDEX);// 得到全部flow

		if (this.netflows == null || this.netflows.size() == 0) {// 如果flow文件没得到，返回
			logger.warning("no flow got in pid:" + PID);
			return Constant.FLOW_NOT_RECEIVED;
		}
		// 开始统计
		this.ipStatistics.setFlows(this.netflows);
		this.ipStatistics.setAS(this.ospfTopo.getAsNumber());
		this.ipStatistics.setNeighborAsIps(this.ospfTopo.getNeighborAsIps());
		this.ipStatisticThread = new Thread(this.ipStatistics);
		this.ipStatisticThread.start();

		// 开始分析flow路径
		this.routeAnalyser.setNetflows(this.netflows);// 将flow给routeAnalyser
		this.routeAnalyser.ospfRouteCalculate(PID, this.netflows.size());// 注意*100原因是数据库中要存储datetime类型，但是pid约定只能精确到分钟，因此这里后面补充秒的占位，计算flow路径

		return Constant.FLOW_ANALYSIS_SUCCESS;
	}

	/**
	 * 其他类获得本类中保存的配置信息的方法
	 * 
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

	private void reportTopoToGlobal() {
		String filePath = FileProcesser.writeResult(this.mapLidTlink,
				this.configData.getInterval());
		// 流量为空 发送全部拓扑给综合分析板卡20130506 modified
		reportData(filePath);
	}

	private void reportPidToGlobal() {
		reportData(null);
	}

	private void reportAllStaticsToGlobal() {
		String filePath = FileProcesser.writeResult(this.mapLidTlink,
				this.ipStatistics.getAllItems(), this.configData.getInterval());// 调用fileProcesser来将得到的路径写入文件中,返回文件路径
		reportData(filePath);
	}

	public void reportData(String filePath) {
		if (this.configData != null) {
			this.resultSender = new ResultSender(PID,
					this.configData.getGlobalAnalysisPort(),
					this.configData.getGlobalAnalysisIP(), filePath);
			new Thread(resultSender).start();// 发送给综合分析板卡
		}
	}

	private void processDeviceFault() {
		this.topoReceiver.getTopoSignal();

		if (this.protocol.equals("ospf")) {
			this.ospfTopo = this.topoReceiver.getOspfTopo();// 得到分析后的ospf拓扑对象

			if (this.ospfTopo == null) {
				reportPidToGlobal();
				return;
			}
		} else {
			this.isisTopo = this.topoReceiver.getIsisTopo();// 得到分析后的isis拓扑对象

			if (this.isisTopo == null) {
				reportPidToGlobal();
				return;
			}
		}
		reportTopoToGlobal();
	}

	/**
	 * 本类中获得配置信息的方法
	 * 
	 * @return
	 */
	private ConfigData getConfig() {
		this.configLock.lock(); // 加锁配置信息对象
		this.configData = this.configReceiver.getConfigData();// 获得配置信息对象
		this.configCondition.signal();// 通知在这个condition上锁住的变量解锁
		this.configLock.unlock();// 解锁配置信息对象
		return this.configData;
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

	public int getPidIndex() {
		return PID_INDEX;
	}

	public static int getInterval() {
		return INTERVAL;
	}

	public void setPid(long pid) {
		PID = pid;
	}
}
