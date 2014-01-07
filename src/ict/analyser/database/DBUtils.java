/*
 * Filename: DBUtils.java
 * Copyright: ICT (c) 2012-12-8
 * Description: 
 * Author: 25hours
 */
package ict.analyser.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Vector;

/**
 * 
 * 程序运行时，不要重启mysql 会 报Broken pipe 异常
 * 
 * @author 25hours
 * @version 1.0, 2012-12-8
 */
public class DBUtils {
	private final static String DRIVER = "com.mysql.jdbc.Driver";
	private final static String URL = "jdbc:mysql://127.0.0.1:3306/netflow?autoReconnect=true";
	private final static String USER = "root";
	private final static String PASSWORD = "qazwsx";
	private static Vector<Connection> pool = new Vector<Connection>();// 去掉了final
	private static final int MAX_SIZE = 10;
	private static final int MIN_SIZE = 3;

	static {
		for (int i = 0; i < MIN_SIZE; i++) {
			pool.add(createConnction());
		}
	}

	private static Connection createConnction() {
		Connection conn = null;
		try {
			Class.forName(DRIVER);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		try {
			conn = DriverManager.getConnection(URL, USER, PASSWORD);
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return conn;
	}

	public static synchronized Connection getConnection() {
		Connection conn = null;

		if (pool.isEmpty()) {
			conn = createConnction();
		} else {
			int last_idx = pool.size() - 1;
			conn = (Connection) pool.get(last_idx);
			pool.remove(conn);
		}

		return conn;
	}

	public static synchronized void close(Connection conn) {
		if (pool.size() < MAX_SIZE) {
			pool.add(conn);
		} else {
			try {
				conn.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}
}
