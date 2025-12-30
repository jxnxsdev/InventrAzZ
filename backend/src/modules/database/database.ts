import { MysqlDatabase } from './mysql';
import { SqliteDatabase } from './sqlite';
import * as defaults from '../../defaults.json';
import fs from 'fs';
import * as logger from '../logger';

let SQLiteDatabase: SqliteDatabase | null = null;
let MySQLDatabase: MysqlDatabase | null = null;

export async function init(): Promise<void> {
  try {
    const useMysql =
      process.env.USE_MYSQL?.toLowerCase() === 'true' ||
      defaults.database.useMySQL;

    if (useMysql) {
      logger.info('Initializing MySQL database connection...');
      MySQLDatabase = new MysqlDatabase(
        process.env.MYSQL_HOST || defaults.database.mySQLLogin.host,
        process.env.MYSQL_USER || defaults.database.mySQLLogin.user,
        process.env.MYSQL_PASSWORD || defaults.database.mySQLLogin.password,
        process.env.MYSQL_DATABASE || defaults.database.mySQLLogin.database
      );
      await MySQLDatabase.connect();
    } else {
      logger.info('Initializing SQLite database connection...');
      const sqlitePath = process.env.SQLITE_PATH || defaults.paths.database;
      const sqliteFile =
        process.env.SQLITE_FILE || defaults.database.SQLiteName;

      if (!fs.existsSync(sqlitePath)) {
        logger.info(
          `SQLite path not found. Creating directory at: ${sqlitePath}`
        );
        fs.mkdirSync(sqlitePath, { recursive: true });
      }

      SQLiteDatabase = new SqliteDatabase(`${sqlitePath}/${sqliteFile}`);
      await SQLiteDatabase.connect();
    }

    logger.info('Database successfully initialized.');
    await initializeTables();
  } catch (error) {
    logger.error(`Database initialization failed: ${(error as Error).message}`);
  }
}

/**
 * Executes a parameterized query to prevent SQL injection.
 * @param query The SQL query string with placeholders.
 * @param params The parameters to bind to the query.
 * @returns Query result.
 */
export async function query(query: string, params: any[] = []): Promise<any> {
  try {
    if (SQLiteDatabase) {
      const connection = await SQLiteDatabase.getConnection();
      return await connection.all(query, params);
    } else if (MySQLDatabase) {
      const connection = await MySQLDatabase.getConnection();
      return await connection.execute(query, params);
    } else {
      throw new Error('No database instance found.');
    }
  } catch (error) {
    logger.error(`Failed to execute query: ${(error as Error).message}`);
    throw error;
  }
}

/**
 * Initializes required tables in the database.
 */
async function initializeTables(): Promise<void> {
  try {
    const createTableQuery = `
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                displayName VARCHAR(255),
                password VARCHAR(255) NOT NULL,
                permissions JSON NOT NULL
            )
        `;
    await query(createTableQuery);
    logger.info('Database tables initialized.');
  } catch (error) {
    logger.error(`Failed to initialize tables: ${(error as Error).message}`);
  }
}
