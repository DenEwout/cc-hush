import os from 'node:os';
import path from 'node:path';

export const DATA = process.env.HUSH_DATA ?? path.join(os.homedir(), '.cc-hush');
export const PORT = 47831;
export const BASE_URL = `http://127.0.0.1:${PORT}`;
export const TOKEN_FILE = path.join(DATA, 'token');
export const CONFIG_FILE = path.join(DATA, 'config.json');
export const LOG_FILE = path.join(DATA, 'daemon.log');
