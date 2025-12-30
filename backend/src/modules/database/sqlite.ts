import sqlite3 from 'sqlite3';
import { open, Database } from 'sqlite';
import * as logger from '../logger';

export class SqliteDatabase {
    private static instance: SqliteDatabase;
    private connection: Database | null = null;
    private path: string;

    constructor(path: string) {
        if (!path) {
            throw new Error('Database path must be provided.');
        }
        this.path = path;
    }

    async connect(): Promise<void> {
        try {
            if (await this.checkConnection()) {
                logger.info('Database connection already established.');
                return;
            }

            this.connection = await open({
                filename: this.path,
                driver: sqlite3.Database, // Use the sqlite3 driver
            });

            logger.info(`Connected to SQLite database at ${this.path}`);
        } catch (error) {
            logger.error(`Failed to connect to SQLite database: ${(error as Error).message}`);
            throw new Error(`Database connection failed: ${(error as Error).message}`);
        }
    }

    async getConnection(): Promise<Database> {
        try {
            if (!await this.checkConnection()) {
                logger.info('No active connection found. Attempting to reconnect...');
                await this.connect();
            }

            if (!this.connection) {
                throw new Error('Connection is not established after reconnect attempt.');
            }

            return this.connection;
        } catch (error) {
            logger.error(`Failed to get database connection: ${(error as Error).message}`);
            throw new Error(`Failed to get database connection: ${(error as Error).message}`);
        }
    }

    private async checkConnection(): Promise<boolean> {
        try {
            if (!this.connection) return false;

            await this.connection.get('SELECT 1');
            return true;
        } catch (error) {
            logger.error(`Database connection check failed: ${(error as Error).message}`);
            return false;
        }
    }
}
