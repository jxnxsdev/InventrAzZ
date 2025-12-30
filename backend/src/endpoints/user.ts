import { Router, Request, Response } from 'express';
import * as defaults from '../defaults.json';
import { Permissions } from '../enums/permissions';
import * as Logger from '../modules/logger';
import * as jwt from 'jsonwebtoken';
import * as database from '../modules/database/database';
import bcrypt from 'bcrypt';
import { authorize } from '../middlewares/auth';
import { getUsernameFromToken } from '../helpers/token';

export const user = Router();

/**
 * Generates a JWT token for authenticated users
 * @param username - The username to encode in the token
 * @param permissions - Array of user permissions
 * @returns JWT token string
 * @throws Error if JWT secret is not configured
 */
const generateToken = (
  username: string,
  permissions: Permissions[]
): string => {
  const secret = process.env.JWT_SECRET || defaults.web.jwtSecret;
  if (!secret) throw new Error('JWT secret is not configured.');
  return jwt.sign({ username, permissions }, secret, {
    expiresIn: '24h'
  });
};

/**
 * Validates user credentials against the database
 * @param username - Username to validate
 * @param password - Password to validate
 * @returns User object with permissions or null if invalid
 */
const validateCredentials = async (username: string, password: string) => {
  try {
    const query = 'SELECT * FROM users WHERE name = ?';
    const result = await database.query(query, [username]);
    if (result.length === 0) return null;

    const user = result[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    return isPasswordValid ? { user } : null;
  } catch (error) {
    Logger.error(`Credential validation error: ${(error as Error).message}`);
    throw error;
  }
};

/**
 * POST /login - Authenticates user and returns JWT token
 */
user.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;
  if (!username || !password) {
    res.status(400).json({ error: 'Missing username or password' });
    return;
  }

  try {
    const credentials = await validateCredentials(username, password);
    if (!credentials) {
      res.status(401).json({ error: 'Invalid username or password' });
      return;
    }

    const token = generateToken(username, credentials.user.permissions || []);
    res.status(200).json({ token });
  } catch (error) {
    Logger.error(`Login error: ${(error as Error).message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /auth - Checks if user is authorized to perform an action
 */
user.post('/auth', async (req: Request, res: Response) => {
  const { user: username, password, action } = req.body;

  if (!username || !password || !action) {
    res.status(401).json({ error: 'Missing username, password, or action' });
    return;
  }

  try {
    const credentials = await validateCredentials(username, password);
    if (!credentials) {
      res.status(401).json({ error: 'Invalid username or password' });
      return;
    }

    const permissions = credentials.user.permissions || [];
    if (
      !permissions.includes(action) &&
      !permissions.includes(Permissions.ALL)
    ) {
      res.status(403).json({ error: 'Forbidden. Insufficient permissions.' });
      return;
    }

    res.status(200).json({ message: 'Action authorized' });
    Logger.info(`User ${username} authorized for action: ${action}`);
  } catch (error) {
    Logger.error(`Auth error: ${(error as Error).message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /create - Creates a new user (requires CREATE_USER permission)
 */
user.post(
  '/create',
  authorize([Permissions.CREATE_USER]),
  async (req: Request, res: Response) => {
    const { username, displayName, password, permissions } = req.body;

    if (!username || !password || !Array.isArray(permissions)) {
      res
        .status(400)
        .json({ error: 'Invalid input. Missing or incorrect data.' });
      return;
    }

    if (
      !permissions.every((perm) => Object.values(Permissions).includes(perm))
    ) {
      res.status(400).json({ error: 'Invalid permissions' });
      return;
    }

    try {
      const existingUserQuery = 'SELECT * FROM users WHERE name = ?';
      const existingUser = await database.query(existingUserQuery, [username]);
      if (existingUser.length > 0) {
        res.status(400).json({ error: 'Username already exists' });
        return;
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const insertQuery =
        'INSERT INTO users (name, displayName, password, permissions) VALUES (?, ?, ?, ?)';
      await database.query(insertQuery, [
        username,
        displayName,
        hashedPassword,
        JSON.stringify(permissions)
      ]);

      res.status(201).json({ message: 'User created' });
      Logger.info(`User ${username} created successfully`);
    } catch (error) {
      Logger.error(`Create user error: ${(error as Error).message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * DELETE /delete - Deletes a user (requires DELETE_USER permission)
 */
user.delete(
  '/delete',
  authorize([Permissions.DELETE_USER]),
  async (req: Request, res: Response) => {
    const { username } = req.body;
    if (!username) {
      res.status(400).json({ error: 'Invalid input. Missing username' });
      return;
    }

    try {
      const existingUserQuery = 'SELECT * FROM users WHERE name = ?';
      const existingUser = await database.query(existingUserQuery, [username]);
      if (existingUser.length === 0) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      const deleteQuery = 'DELETE FROM users WHERE name = ?';
      await database.query(deleteQuery, [username]);

      res.status(200).json({ message: 'User deleted' });
      Logger.info(`User ${username} deleted successfully`);
    } catch (error) {
      Logger.error(`Delete user error: ${(error as Error).message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * GET /list - Lists all users (requires VIEW_USERS permission)
 */
user.get(
  '/list',
  authorize([Permissions.VIEW_USERS]),
  async (req: Request, res: Response) => {
    try {
      const query = 'SELECT id, name, displayName, permissions FROM users';
      const users = await database.query(query);

      const userList = users.map((user: any) => ({
        id: user.id,
        name: user.name,
        displayName: user.displayName,
        permissions: JSON.parse(user.permissions)
      }));

      res.status(200).json({ users: userList });
    } catch (error) {
      Logger.error(`List users error: ${(error as Error).message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * GET /permissionslist - Returns all available permissions
 */
user.get(
  '/permissionslist',
  authorize(),
  async (req: Request, res: Response) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      res.status(401).json({ error: 'Access denied. No token provided.' });
      return;
    }

    try {
      const permissions = Object.values(Permissions);
      res.status(200).json({ permissions });
    } catch (error) {
      Logger.error(`Get permissions error: ${(error as Error).message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * GET /selfinfo - Returns current user's information
 */
user.get('/selfinfo', authorize(), async (req: Request, res: Response) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(401).json({ error: 'Access denied. No token provided.' });
    return;
  }

  try {
    const username = await getUsernameFromToken(token);
    if (!username) {
      res.status(401).json({ error: 'Invalid or expired token' });
      return;
    }

    const query = 'SELECT displayName, permissions FROM users WHERE name = ?';
    const result = await database.query(query, [username]);
    if (result.length === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    res.status(200).json({
      displayName: result[0].displayName,
      permissions: JSON.parse(result[0].permissions)
    });
  } catch (error) {
    Logger.error(`Get user info error: ${(error as Error).message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /usertableempty - Checks if user table is empty
 */
user.get('/usertableempty', async (req: Request, res: Response) => {
  try {
    const query = 'SELECT COUNT(*) as count FROM users';
    const result = await database.query(query);
    const isEmpty = result[0].count === 0;
    res.status(200).json({ isEmpty });
  } catch (error) {
    Logger.error(`Check empty table error: ${(error as Error).message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /createadmin - Creates admin user (only if no users exist)
 */
user.post('/createadmin', async (req: Request, res: Response) => {
  const { username, displayName, password } = req.body;
  if (!username || !password) {
    res
      .status(400)
      .json({ error: 'Invalid input. Missing or incorrect data.' });
    return;
  }

  try {
    const query = 'SELECT COUNT(*) as count FROM users';
    const result = await database.query(query);
    const isEmpty = result[0].count === 0;

    if (!isEmpty) {
      res
        .status(403)
        .json({ error: 'Admin user can only be created if no users exist.' });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const insertQuery =
      'INSERT INTO users (name, displayName, password, permissions) VALUES (?, ?, ?, ?)';
    await database.query(insertQuery, [
      username,
      displayName,
      hashedPassword,
      JSON.stringify([Permissions.ALL])
    ]);

    res.status(201).json({ message: 'Admin user created' });
    Logger.info(`Admin user ${username} created successfully`);
  } catch (error) {
    Logger.error(`Create admin user error: ${(error as Error).message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});
