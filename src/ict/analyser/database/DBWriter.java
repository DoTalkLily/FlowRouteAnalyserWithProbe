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
import java.sql.SQLException;
import java.util.ArrayList;

public class DBWriter {

	private String sql = "insert into netflow values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

	// private int counter = 0;
	public boolean writeToDB(ArrayList<Flow> flows) {

		Connection conn = DBUtils.getConnection();// 从线程池中获得一个连接

		try {

			if (!conn.isClosed()) {
				int size = flows.size();
				Flow oneFlow = null;
				Netflow netflow = null;

				System.out.println("数据库连接成功");
				// 数据库连接成功，开始存入NetFlow数据
				PreparedStatement pstmt = conn.prepareStatement(this.sql);

				int counter = 0;

				for (int i = 0; i < size; i++) {
					oneFlow = flows.get(i);
					netflow = oneFlow.getNetflow();

					if (netflow != null) {
						pstmt.setLong(1, oneFlow.getPid());
						pstmt.setLong(2, netflow.getSrcAddr());
						pstmt.setLong(3, netflow.getDstAddr());
						pstmt.setInt(4, netflow.getSrcPort());
						pstmt.setInt(5, netflow.getDstPort());
						pstmt.setByte(6, netflow.getProtocol());
						pstmt.setLong(7, netflow.getdOctets());
						pstmt.setInt(8, netflow.getSrcAs());
						pstmt.setInt(9, netflow.getDstAs());
						pstmt.setLong(10, netflow.getSrcPrefix());
						pstmt.setLong(11, netflow.getDstPrefix());
						pstmt.setInt(12, netflow.getInput());
						pstmt.setInt(13, netflow.getOutput());
						pstmt.setString(14, oneFlow.getPath()
								.getPathInIpFormat());
						pstmt.setLong(15, netflow.getFirst());
						pstmt.setLong(16, netflow.getLast());
						pstmt.setShort(17, netflow.getProc());

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
}
