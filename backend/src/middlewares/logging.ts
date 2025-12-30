import { Request, Response, NextFunction } from 'express';
import * as Logger from '../modules/logger';

export const logRequest = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown IP';
  const method = req.method;
  const url = req.originalUrl;
  const userAgent = req.headers['user-agent'] || 'unknown agent';
  const msg = `Request from ${ip}: ${method} ${url} - Agent: ${userAgent}`;
  await Logger.request(msg);
  next();
};
