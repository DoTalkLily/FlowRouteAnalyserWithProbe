package ict.analyser.database;

/**
 * 修改记录：20130515  把目的接口信息存成了源接口信息, 目的和源顺序调过来
 * pstmt.setLong(18, oneFlow.getPath().getSrcInterface());
 * 改成 pstmt.setLong(18, oneFlow.getPath().getDstInterface());
 */
import ict.analyser.common.Constant;
import ict.analyser.flow.Flow;
import ict.analyser.netflow.Netflow;
import ict.analyser.tools.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;

public class DBOperator {
	public boolean writeFlowToDB(long pid, ArrayList<Flow> flows) {
		String sql;
		Connection conn;

		sql = "insert into netflow" + pid / 10000
				+ " values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
		conn = DBUtils.getConnection();// 从线程池中获得一个连接

		try {
			if (!conn.isClosed()) {
				int size = flows.size();
				Flow oneFlow = null;
				Netflow netflow = null;

				// System.out.println("数据库连接成功");
				// 数据库连接成功，开始存入NetFlow数据
				PreparedStatement pstmt = conn.prepareStatement(sql);

				int counter = 0;
				int hourFrom2013 = Utils.pid2HourOfYear(pid);

				for (int i = 0; i < size; i++) {
					oneFlow = flows.get(i);
					netflow = oneFlow.getNetflow();

					if (netflow != null) {
						pstmt.setLong(1, pid);
						pstmt.setLong(2, netflow.getSrcAddr());
						pstmt.setLong(3, netflow.getDstAddr());
						pstmt.setByte(4, netflow.getSrcMask());
						pstmt.setByte(5, netflow.getDstMask());
						pstmt.setLong(6, netflow.getSrcRouter());
						pstmt.setLong(7, netflow.getDstRouter());
						pstmt.setInt(8, netflow.getSrcPort());
						pstmt.setInt(9, netflow.getDstPort());
						pstmt.setLong(10, netflow.getdOctets());
						pstmt.setInt(11, netflow.getSrcAs());
						pstmt.setInt(12, netflow.getDstAs());
						pstmt.setLong(13, netflow.getSrcPrefix());
						pstmt.setLong(14, netflow.getDstPrefix());
						pstmt.setInt(15, netflow.getInput());
						pstmt.setInt(16, netflow.getOutput());
						pstmt.setInt(17, netflow.getTos());
						pstmt.setString(18, oneFlow.getPath()
								.getPathInIpFormat());
						pstmt.setLong(19, netflow.getFirst());
						pstmt.setLong(20, netflow.getLast());
						pstmt.setShort(21, netflow.getProc());
						pstmt.setLong(22, netflow.getRouterIP());
						pstmt.setInt(23, hourFrom2013);
						conn.setAutoCommit(false);// 重要！不然自动提交
						pstmt.addBatch();// 用PreparedStatement的批量处理
						counter++;

						if (counter >= 1000) {// 为了避免缓存溢出
							counter = 0;
							pstmt.executeBatch();// 执行批处理
							conn.commit();
							pstmt.clearBatch();
						}
					}
				}
				conn.setAutoCommit(false);
				pstmt.executeBatch();// 执行批处理
				conn.commit();
				pstmt.close();
				return true;
			}
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			DBUtils.close(conn);
		}

		return false;
	}

	public static ResultSet queryFlow(String sql) {
		if (sql == null) {
			return null;
		}

		Connection conn = DBUtils.getConnection();// 从线程池中获得一个连接
		if (conn == null)
			System.out.println("conn is null!!!");
		try {
			if (!conn.isClosed()) {
				Statement statement = conn.createStatement();
				ResultSet set = statement.executeQuery(sql);
				return set;
			}
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			DBUtils.close(conn);
		}
		return null;
	}

	public static void createTable(long pid) {
		if (pid <= 0) {
			return;
		}

		String sql;
		Connection conn;
		Statement statement;
		conn = DBUtils.getConnection();

		try {
			statement = conn.createStatement();
			sql = "drop table if exists netflow" + (pid / 10000);
			statement.execute(sql);
			sql = "create table netflow" + (pid / 10000)
					+ Constant.CREATE_TABLE;
			statement.execute(sql);
			statement.close();
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			DBUtils.close(conn);
		}
	}
}
