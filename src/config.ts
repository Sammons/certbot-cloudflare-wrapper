import * as fs from 'fs';
import * as path from 'path';
import { logger } from './logging';
const configPath = path.resolve(__dirname, '../config.json');

if (!fs.existsSync(configPath)) {
  logger.info('config.json is missing!');
  process.exit(1);
}
let parsedConfig: { [k: string]: string | number } = {};

try {
  parsedConfig = JSON.parse(fs.readFileSync(configPath).toString());
} catch (err) {
  logger.info('Config file contains invalid json!', err.message);
  process.exit(1);
}

const keysMissing = [] as string[];
const access = <T>(o: T, key: string) => {
  if (parsedConfig[key] == null) {
    keysMissing.push(key);
  }
  return parsedConfig[key];
};

const terminate = () => {
  process.nextTick(process.exit, 1);
};

export const config = {
  port: Number(access(parsedConfig, 'port')),
  domains: access(parsedConfig, 'domains') as any as string[],
  socketPath: access(parsedConfig, 'socketPath'),
  email: access(parsedConfig, 'email'),
  cloudflareKey: access(parsedConfig, 'cloudflareKey'),
  staging: access(parsedConfig, 'staging'),
};
const validate = () => {
  if (keysMissing.length > 0) {
    logger.error('Missing keys in the configuration!');
    return terminate();
  }

  if (!Number.isInteger(config.port)) {
    logger.error('Port is not a number?', { port: config.port });
    return terminate();
  }

  if (!Array.isArray(config.domains)) {
    logger.error('Domains is not an array?', { domains: config.domains });
    return terminate();
  }
};

validate();
