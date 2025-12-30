import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';
import { Permissions } from '../enums/permissions';
import * as Logger from '../modules/logger';
import * as defaults from '../defaults.json';

interface AuthPayload {
    username: string;
    permissions: Permissions[];
}

export const authorize =
    (requiredPermissions: Permissions[] = []) =>
    (req: Request, res: Response, next: NextFunction): void => {
        const token = req.headers.authorization?.split(' ')[1]; // Expect "Bearer <token>"

        if (!token) {
            res.status(401).json({ error: 'Access denied. No token provided.' });
            return;
        }

        try {
            const secret = process.env.JWT_SECRET || defaults.web.jwtSecret;
            const decoded = jwt.verify(token, secret) as AuthPayload;

            // @ts-ignore
            req.user = {
                username: decoded.username,
                permissions: decoded.permissions,
            };

            if (decoded.permissions.includes(Permissions.ALL)) {
                next();
                return;
            }

            if (requiredPermissions.length > 0 && !requiredPermissions.some((permission) => decoded.permissions.includes(permission))) {
                res.status(403).json({ error: 'Access denied. Insufficient permissions.' });
                return;
            }

            next();
        } catch (error) {
            Logger.error(`Authorization error: ${(error as Error).message}`);
            res.status(401).json({ error: 'Invalid or expired token.' });
        }
    };
