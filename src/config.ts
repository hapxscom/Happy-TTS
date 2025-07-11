import dotenv from 'dotenv';
import { join } from 'path';

dotenv.config();

interface Config {
  port: string | number;
  openai: {
    apiKey: string | undefined;
    baseUrl: string | undefined;
  };
  server: {
    password: string;
  };
  paths: {
    ipData: string;
    lcData: string;
    logs: string;
    finish: string;
    data: string;
  };
  limits: {
    maxRequestsPerMinute: number;
    maxRequestsPerHour: number;
    maxRequestsPerDay: number;
  };
  ip: {
    whitelist: string[];
  };
}

const config: Config = {
  port: process.env.PORT || 3000,
  openai: {
    apiKey: process.env.OPENAI_API_KEY,
    baseUrl: process.env.OPENAI_BASE_URL,
  },
  server: {
    password: process.env.SERVER_PASSWORD || 'admin',
  },
  paths: {
    ipData: join(__dirname, '../data/ip_data.json'),
    lcData: join(__dirname, '../data/lc_data.json'),
    logs: join(__dirname, '../data/logs'),
    finish: join(__dirname, '../data/finish'),
    data: join(__dirname, '../data'),
  },
  limits: {
    maxRequestsPerMinute: 60,
    maxRequestsPerHour: 1000,
    maxRequestsPerDay: 10000,
  },
  ip: {
    whitelist: (process.env.IP_WHITELIST || '').split(',').filter(Boolean),
  },
};

export const enableTurnstile = process.env.VITE_ENABLE_TURNSTILE === 'true';

export default config; 