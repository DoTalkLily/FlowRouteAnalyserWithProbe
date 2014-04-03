package ict.analyser.netflow;

import ict.analyser.collector.Params;
import ict.analyser.tools.Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Properties;

/**
 * 
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-19
 */
public class Template {
	private int templateId = 0;// 模板id
	private int wholeOffset = 0;// 模板的所有属性的offset和
	private int samplingRate = 1;// 采样率
	private String routerIp = null;// 路由器ip
	final static int MAX_TYPE = 93;// 模板中属性对应的最大值上限
	private int[] lenOftypes = new int[MAX_TYPE];// 模板中属性的长度
	private int[] offsetOftypes = new int[MAX_TYPE];// 模板中属性的位移
	private Properties property = new Properties();// 将模板格式文件中的键值对载入
	static String templatePath = Params.path + "\\etc\\templates\\";// 模板文件存储路径

	/**
	 * 从文件名得到路由器ip和template id，文件名格式 x.x.x.x_templateId.properties，然后初始化模板
	 * 
	 * @param fileName
	 */
	public Template(String fileName) {

		int beginIdx = fileName.lastIndexOf("\\");

		if (beginIdx < 0) {
			beginIdx = 0;
		} else {
			beginIdx += 1;
		}

		String routerIp = fileName.trim().substring(beginIdx,
				fileName.indexOf("_"));
		String templateIdStr = fileName.trim().substring(
				fileName.indexOf("_") + 1, fileName.lastIndexOf("."));

		int tid = Integer.parseInt(templateIdStr);

		makeTemplate(routerIp, tid);
	}

	/**
	 * 用将flowset中的byte提取成一个template，初始化变量并将template写入文件
	 * 
	 * @param routerIp
	 * @param flowset
	 * @param templateOffset
	 */
	public Template(String routerIp, byte[] flowset, int templateOffset) {

		int tid = Utils.byte2int(flowset, templateOffset);

		if (tid < 0 || tid > 255) {// 0-255 reserved for flowset IDs
			int fieldCnt = Utils.byte2int(flowset, templateOffset + 2);
			Properties property = new Properties();
			templateOffset += 4;

			// int dataFlowSetOffset = 4;// after the flowSetID and length

			int dataFlowSetOffset = 0;

			for (int idx = 0; idx < fieldCnt; idx++) {
				int typeName = Utils.byte2int(flowset, templateOffset);
				templateOffset += 2;
				int typeLen = Utils.byte2int(flowset, templateOffset);
				templateOffset += 2;

				if (typeName < MAX_TYPE && typeName > 0) {
					property.setProperty(new Integer(typeName).toString(),
							new Integer(dataFlowSetOffset).toString());
					this.offsetOftypes[typeName] = dataFlowSetOffset;
					this.lenOftypes[typeName] = typeLen;
				}
				dataFlowSetOffset += typeLen;
			}

			if (property.size() <= 0) {// if nothing is inputted
				System.err.println("No field type in the template");
			}

			property.setProperty(new Integer(-1).toString(), new Integer(
					dataFlowSetOffset).toString());
			wholeOffset = dataFlowSetOffset;
			this.makeTemplate(routerIp, property, tid);
		} else {
			System.err.println("Template id is illegal");
		}
	}

	/**
	 * 根据路由器ip 和tempate id 载入一个模板
	 * 
	 * @param routerIp
	 * @param tid
	 */
	public Template(String routerIp, int tid) {
		makeTemplate(routerIp, tid);
	}

	/**
	 * 从文件中载入模板
	 * 
	 * @param routerIp
	 * @param tid
	 */
	@SuppressWarnings("rawtypes")
	public void makeTemplate(String routerIp, int tid) {

		this.routerIp = routerIp;
		this.templateId = tid;

		String fullName = null;

		if (routerIp.indexOf(File.separator) == -1) {
			fullName = templatePath + routerIp;
		} else {
			fullName = routerIp;
		}

		File propFile = new File(fullName + "_" + tid + ".properties");

		if (propFile.exists()) {
			InputStream propIn = null;
			try {
				propIn = new FileInputStream(propFile);
				property.load(propIn);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

		} else {
			System.err.println(propFile + "不存在");
		}

		wholeOffset = Integer.parseInt(property.getProperty("-1"));
		if (property != null) {
			for (Enumeration theKeys = property.propertyNames(); theKeys
					.hasMoreElements();) {
				String key = theKeys.nextElement().toString();
				int typeName = Integer.parseInt(key);
				if (typeName > 0 && typeName < Template.MAX_TYPE) {
					int offset = Integer.parseInt(property.getProperty(key));
					this.offsetOftypes[typeName] = offset;
					this.lenOftypes[typeName] = wholeOffset - offset;// ���ﲻ��+1����ǰ��offset+length����
				}
			}
			for (Enumeration theKeys = property.propertyNames(); theKeys
					.hasMoreElements();) {
				String key = theKeys.nextElement().toString();
				int typeName = Integer.parseInt(key);
				if (typeName > 0 && typeName < Template.MAX_TYPE) {
					if (typeName == 11) {
						System.out.println("");
					}
					for (int i = 0; i < offsetOftypes.length; i++) {
						if (offsetOftypes[i] >= 0
								&& (offsetOftypes[i] - offsetOftypes[typeName] > 0)
								&& (offsetOftypes[i] - offsetOftypes[typeName] < lenOftypes[typeName])) {
							lenOftypes[typeName] = offsetOftypes[i]
									- offsetOftypes[typeName];
						}
					}
				}
			}
		}
	}

	/**
	 * 将template 写入文件
	 * 
	 * @param routerIp
	 * @param properties
	 * @param tid
	 */

	public void makeTemplate(String routerIp, Properties properties, int tid) {
		property = properties;
		templateId = tid;
		setRouterIp(routerIp);
		if (property != null) {
			File propFile = new File(templatePath + routerIp + "_" + tid
					+ ".properties");
			if (propFile.exists()) {
				propFile.delete();
			}
			OutputStream propOut;
			try {
				propOut = new FileOutputStream(propFile);
				property.store(propOut, "template of " + tid + " " + routerIp);
				propOut.flush();
				propOut.close();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

		} else {
			System.err.println("Template is null");
		}
	}

	/**
	 * 返回一个type name 在template中的偏移
	 * 
	 * @param typeName
	 * @return
	 */
	public int getTypeOffset(int typeName) {
		if (typeName > 0 && typeName < MAX_TYPE) {
			if (this.offsetOftypes[typeName] == 0) {
				String value = this.property.getProperty(new Integer(typeName)
						.toString());
				if (value != null) {
					offsetOftypes[typeName] = Integer.parseInt(value);
				}
			}
			return offsetOftypes[typeName];
		} else if (typeName == -1) {
			return wholeOffset;
		} else {
			return -1;
		}
	}

	/**
	 * 根据属性名得到属性长度
	 * 
	 * @param typeName
	 * @return
	 */
	public int getTypeLen(int typeName) {
		if (typeName > 0 && typeName < MAX_TYPE) {
			return lenOftypes[typeName];
		}
		return 0;
	}

	/**
	 * @return Returns the templateId.
	 */
	public int getTemplateId() {
		return templateId;
	}

	/**
	 * @param templateId
	 *            The templateId to set.
	 */
	public void setTemplateId(int templateId) {
		this.templateId = templateId;
	}

	/**
	 * @return Returns the samplingRate.
	 */
	public int getSamplingRate() {
		return samplingRate;
	}

	/**
	 * @param samplingRate
	 *            The samplingRate to set.
	 */
	public void setSamplingRate(int samplingRate) {
		this.samplingRate = samplingRate;
	}

	/**
	 * @return Returns the wholeOffset.
	 */
	public int getWholeOffset() {
		return wholeOffset;
	}

	/**
	 * @param wholeOffset
	 *            The wholeOffset to set.
	 */
	public void setWholeOffset(int wholeOffset) {
		this.wholeOffset = wholeOffset;
	}

	/**
	 * @return Returns the routerIp.
	 */
	public String getRouterIp() {
		return routerIp;
	}

	/**
	 * @param routerIp
	 *            The routerIp to set.
	 */
	public void setRouterIp(String routerIp) {
		this.routerIp = routerIp;
	}
}
