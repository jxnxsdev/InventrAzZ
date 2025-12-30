import jwt from "jsonwebtoken";
import { Permissions } from "../enums/permissions";
import * as defaults from "../defaults.json";

interface AuthPayload {
    username: string;
    permissions: Permissions[];
}

export async function getUsernameFromToken(token: string): Promise<string> {
    try {
        const secret = process.env.JWT_SECRET || defaults.web.jwtSecret;
        const decoded = jwt.verify(token, secret) as AuthPayload;
        return decoded.username;
    }
    catch (error) {
        console.error(`Authorization error: ${(error as Error).message}`);
        return "";
    }
}