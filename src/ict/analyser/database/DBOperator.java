package ict.analyser.database;

/**
 * 修改记录：20130515  把目的接口信息存成了源接口信息, 目的和源顺序调过来
 * pstmt.setLong(18, oneFlow.getPath().getSrcInterface());
 * 改成 pstmt.setLong(18, oneFlow.getPath().getDstInterface());
 */
import ict.analyser.flow.Flow;
import ict.analyser.netflow.Netflow;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;

public class DBOperator {
	public boolean writeFlowToDB(ArrayList<Flow> flows) {
		String sql = "insert into netflow values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

		Connection conn = DBUtils.getConnection();// 从线程池中获得一个连接

		try {
			if (!conn.isClosed()) {
				int size = flows.size();
				Flow oneFlow = null;
				Netflow netflow = null;

				System.out.println("数据库连接成功");
				// 数据库连接成功，开始存入NetFlow数据
				PreparedStatement pstmt = conn.prepareStatement(sql);

				int counter = 0;

				for (int i = 0; i < size; i++) {
					oneFlow = flows.get(i);
					netflow = oneFlow.getNetflow();

					if (netflow != null) {
						pstmt.setLong(1, oneFlow.getPid());
						pstmt.setLong(2, netflow.getSrcAddr());
						pstmt.setLong(3, netflow.getDstAddr());
						pstmt.setLong(4, netflow.getSrcRouter());
						pstmt.setLong(5, netflow.getDstRouter());
						pstmt.setInt(6, netflow.getSrcPort());
						pstmt.setInt(7, netflow.getDstPort());
						pstmt.setByte(8, netflow.getProtocol());
						pstmt.setLong(9, netflow.getdOctets());
						pstmt.setInt(10, netflow.getSrcAs());
						pstmt.setInt(11, netflow.getDstAs());
						pstmt.setLong(12, netflow.getSrcPrefix());
						pstmt.setLong(13, netflow.getDstPrefix());
						pstmt.setInt(14, netflow.getInput());
						pstmt.setInt(15, netflow.getOutput());
						pstmt.setInt(16, netflow.getTos());
						pstmt.setString(17, oneFlow.getPath()
								.getPathInIpFormat());
						pstmt.setLong(18, netflow.getFirst());
						pstmt.setLong(19, netflow.getLast());
						pstmt.setShort(20, netflow.getProc());

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
}
