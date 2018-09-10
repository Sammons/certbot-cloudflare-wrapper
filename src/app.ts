import * as child_process from 'child_process';
import * as crypto from 'crypto';
import * as dockerode from 'dockerode';
import * as express from 'express';
import * as fs from 'fs';
import * as _ from 'lodash';
import * as os from 'os';
import * as path from 'path';
import * as util from 'util';
import { config } from './config';
import { logger } from './logging';

const fsp = {
  readFile: util.promisify(fs.readFile),
  exists: util.promisify(fs.exists),
  appendFile: util.promisify(fs.appendFile),
  stat: util.promisify(fs.stat),
  open: util.promisify(fs.open),
};

if (!fs.existsSync(`./history`)) {
  fs.mkdirSync(`./history`);
}
const historyFilePath = `./history/history.txt`;
if (!fs.existsSync(historyFilePath)) {
  fs.writeFileSync(historyFilePath, '');
}
// maybe not the best reverse-stream ever, but this does not need to be fast
const readLinesFromHistoryFile = async (count: number): Promise<string[]> => {
  const resultLines: string[] = [];
  // stat the file
  const stats = await fsp.stat(historyFilePath);
  const readFrame = async (lastStagger: string, start: number, end: number) => {
    const part: Buffer = await new Promise<Buffer>((resolve, reject) => {
      const stream = fs.createReadStream(historyFilePath, {
        start, end,
      });
      stream.on('error', reject);
      const pieces: Buffer[] = [];
      stream.on('data', (chunk: Buffer) => {
        pieces.push(chunk);
      });
      stream.on('close', () => {
        resolve(Buffer.concat([...pieces, Buffer.from(lastStagger, 'utf8')]));
      });
    });
    const lines = part.toString('utf8').split(/\n/gm);
    const currentStagger = lines.shift() || '';
    return {
      stagger: currentStagger,
      lines,
    };
  };
  const chunkSize = 16 * 1024; // 16kb
  let curStart = stats.size - chunkSize;
  if (curStart < 0) {
    curStart = 0;
  }
  let curEnd = stats.size;
  let stagger = '';
  while (curStart >= 0 && resultLines.length < count) {
    const result = await readFrame(stagger, curStart, curEnd);
    stagger = result.stagger;
    resultLines.unshift(...result.lines);
    curEnd = curStart - 1;
    curStart -= chunkSize;
  }
  return resultLines.slice(-count);
};

export class App {

  get dockerode() {
    return new dockerode({
      socketPath: config.socketPath as string,
    });
  }

  get credentialFile() {
    return path.resolve(`${process.cwd()}/credentials.txt`);
  }

  public actions: Array<{
    timestamp: string;
    action: string;
    domain: string;
  }> = [];

  // the provisioner library uses md5 on domain keys to determine their suffix
  public md5(s: string) {
    return crypto.createHash('md5').update(s.trim()).digest('hex');
  }

  public async getAffectedServices(domain: string) {
    // get .crt and .pem secrets
    const domainSecrets = await this.secrets(domain);
    const domainSecretIds = new Set<string>(domainSecrets.map((domainSecret) => _.get(domainSecret, 'ID')));
    logger.info(`Detected ${domainSecrets.length} secrets for domain ${domain}`);
    // detect services which use the secrets
    const services = await this.dockerode.listServices();
    return services.filter((service) => {
      if (_.get(service, 'Spec.Name', '').startsWith(os.hostname)) {
        logger.info(`Ignoring service ${service.Spec.Name} since it is actually this service...`);
        return false;
      }
      const serviceSecrets = _.get(service, 'Spec.TaskTemplate.ContainerSpec.Secrets', []);
      const serviceName = _.get(service, 'Spec.Name');
      logger.info(`Testing service "${serviceName}" to see if affected by domain "${domain}"`);
      return serviceSecrets.some((secret: any) => {
        const serviceSecretId = _.get(secret, 'SecretID');
        return domainSecretIds.has(serviceSecretId);
      });
    });
  }
  // TODO: extract secrets back out of the file system
  // TODO: update affected services with those secrets

  public async extractSecrets(domain: string) {
    const prefix = crypto.randomBytes(3).toString('hex').toUpperCase();
    const crtSuffix = this.md5(`${domain}.crt`);
    const pemSuffix = this.md5(`${domain}.pem`);
    const domainDir = `/etc/letsencrypt/live/${domain}`;
    const crtPath = path.resolve(`${domainDir}/fullchain.pem`);
    const pemPath = path.resolve(`${domainDir}/privkey.pem`);
    if (!await fsp.exists(domainDir)) {
      logger.warn(`Directory ${domainDir} does not exist! Not creating secrets for ${domain}.`);
      return;
    }
    if (!await fsp.exists(crtPath)) {
      logger.warn(`File ${crtPath} does not exist! Not creating secrets for ${domain}`);
      return;
    }
    if (!await fsp.exists(pemPath)) {
      logger.warn(`File ${pemPath} does not exist! Not cerating secrets for domain ${domain}`);
      return;
    }
    const crtStats = await fsp.stat(crtPath);
    // check if cert created in the last 5 minutes
    if ((new Date().getTime() - crtStats.ctime.getTime()) > (1000 * 60 * 5)) {
      logger.info(`Skipping creating a new secret for ${domain} since the cert is not new`);
      return;
    }
    const crt = await fsp.readFile(crtPath);
    const pem = await fsp.readFile(pemPath);
    const crtSecretName = `${prefix}_external_secret_${crtSuffix}`;
    const pemSecretName = `${prefix}_external_secret_${pemSuffix}`;
    logger.info(`Creating secrets for domain ${domain}`, {
      domain,
      secrets: [crtSecretName, pemSecretName],
    });
    const [crtCreated, pemCreated] = await Promise.all([
      this.dockerode.createSecret({
        Name: crtSecretName,
        Data: crt.toString('base64'),
      }),
      this.dockerode.createSecret({
        Name: pemSecretName,
        Data: pem.toString('base64'),
      }),
    ]);
    logger.info(`Successfully created secrets for domain ${domain}`, {
      crtSecretName, pemSecretName,
    });
    return {
      crtCreatedId: crtCreated.id,
      pemCreatedId: pemCreated.id,
      crtSecretName,
      pemSecretName,
      crtSuffix,
      pemSuffix,
    };
  }

  public async appendAction(action: {
    serviceId: string;
    serviceName: string;
    oldSecrets: Array<{ secretId: string; secretName: string; }>;
    newSecrets: Array<{ secretId: string; secretName: string; }>;
    timestamp: string;
  }) {
    await fsp.appendFile(historyFilePath, JSON.stringify(action) + '\n');
  }

  public async apply() {
    for (const domain of config.domains) {
      logger.info('Processing domain', { domain });
      const services = await this.getAffectedServices(domain);
      logger.info(`Services affected by ${domain}`, {
        services: _.map(services, (service) => _.get(service, 'Spec.Name')),
      });
      if (services.length === 0) {
        logger.info(`Skipping domain ${domain}, since it has no affected services`);
        continue;
      }
      logger.info(`Acquiring/Renewing domain ${domain}`);
      try {
        const stagingFlag = config.staging ? ` --staging ` : ``;
        await new Promise((res, rej) => {
          child_process.exec(
            `certbot certonly --dns-cloudflare -n --agree-tos ${stagingFlag} -m ${config.email} -d "${domain}" ` +
            ` --dns-cloudflare-credentials=${this.credentialFile}`, {
              shell: '/bin/sh',
            }, (error, stdout, stderr) => {
              if (error) {
                rej(error);
              } else {
                res({
                  stdout, stderr,
                });
              }
            },
          );
        });
        logger.info(`Completed executing certbot command.`);
      } catch (error) {
        logger.error(`Failed to run certbot for domain ${domain}`, error);
      }
      const domainSecrets = await this.extractSecrets(domain);
      if (domainSecrets) {
        logger.info(`Updating services affected by domain ${domain} with new secrets`, {
          domain,
          domainSecrets,
          services: services.map((service) => _.get(service, 'Spec.Name')),
        });
        for (const service of services) {
          const serviceName = service.Spec.Name;
          const secrets = service.Spec.TaskTemplate.ContainerSpec.Secrets;
          logger.info(`Modifying secrets on service ${service.Spec.Name}`, {
            secrets,
          });
          let somethingUpdated = false;
          // for audit trail
          const oldSecrets = new Array<{ secretId: string; secretName: string; }>();
          const newSecrets = new Array<{ secretId: string; secretName: string; }>();
          secrets.forEach((secret: { SecretName: string; SecretID: string; }) => {
            if (secret.SecretName.endsWith(domainSecrets.crtSuffix)) {
              somethingUpdated = true;
              logger.info(
                `Replacing ${secret.SecretName} with ${domainSecrets.crtSecretName} on service ${serviceName}`,
              );
              oldSecrets.push({
                secretId: secret.SecretID,
                secretName: secret.SecretName,
              });
              secret.SecretName = domainSecrets.crtSecretName;
              secret.SecretID = domainSecrets.crtCreatedId;
              newSecrets.push({
                secretId: secret.SecretID,
                secretName: secret.SecretName,
              });
            }
            if (secret.SecretName.endsWith(domainSecrets.pemSuffix)) {
              somethingUpdated = true;
              logger.info(
                `Replacing ${secret.SecretName} with ${domainSecrets.pemSecretName} on service ${serviceName}`,
              );
              oldSecrets.push({
                secretId: secret.SecretID,
                secretName: secret.SecretName,
              });
              secret.SecretID = domainSecrets.pemCreatedId;
              secret.SecretName = domainSecrets.pemSecretName;
              newSecrets.push({
                secretId: secret.SecretID,
                secretName: secret.SecretName,
              });
            }
          });
          if (somethingUpdated) {
            logger.info(`Attempting to apply the modifications, changing service at version ${service.Version.Index}`);
            const attemptUpdate = async () => {
              const latestService = await this.dockerode.getService(service.ID).inspect();
              latestService.Spec.TaskTemplate.ContainerSpec.Secrets = secrets;
              await this.dockerode.getService(service.ID).update({
                ...latestService.Spec,
                version: Number(service.Version.Index),
              });
              logger.info(`Updated service ${serviceName}`);
            };
            let count = 0;
            while (count < 3) {
              try {
                await attemptUpdate();
                const action = {
                  serviceId: service.ID,
                  serviceName,
                  oldSecrets,
                  newSecrets,
                  timestamp: new Date().toISOString(),
                };
                await this.appendAction(action);
              } catch (error) {
                logger.error(`Failed to apply change to service ${serviceName}`);
              }
              count++;
            }
          } else {
            logger.info(`No changes detected.`);
          }
        }
      } else {
        logger.warn(`Not updating services for domain ${domain}, the pem & crt do not exist!?`);
        return;
      }
    }
  }
  public async run() {
    await util.promisify(fs.writeFile)(this.credentialFile, [
      `dns_cloudflare_email = ${config.email}`,
      `dns_cloudflare_api_key = ${config.cloudflareKey}`,
    ].join('\n') + '\n', {
        mode: '0400',
      });
    const server = express();
    server.get('/history', async (req, res) => {
      try {
        const history = (await readLinesFromHistoryFile(100));
        console.log('History');
        res.json(
          history.filter((l) => l.trim().length > 0).map((l) => JSON.parse(l)),
        );
      } catch (e) {
        res.status(500).json({
          message: e.message,
          stack: e.stack.split('\n'),
        });
      }
    });
    server.listen(config.port, () => {
      logger.info('listening on port', { port: config.port });
    });
    this.apply();
    const scheduleNext = () => {
      setTimeout(() => {
        this.apply();
        process.nextTick(scheduleNext);
      }, 6 /* hour */ * 60 /* min */ * 60 /* sec */ * 1000 /* ms */);
    };
    scheduleNext();
  }

  private async secrets(domain: string) {
    const suffixes = {
      crt: this.md5(`${domain}.crt`),
      key: this.md5(`${domain}.pem`),
    };
    const secrets = await this.dockerode.listSecrets();
    return _.filter(secrets, (s) => {
      const name: string | undefined = _.get(s, ['Spec', 'Name']);
      return name && (name.endsWith(suffixes.crt) || name.endsWith(suffixes.key));
    });
  }
}
