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
    const prefix = crypto.randomBytes(3).toString('hex');
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
    const crt = await fsp.readFile(crtPath);
    const pem = await fsp.readFile(pemPath);
    const crtSecretName = `${prefix}_external_secret_${crtSuffix}`;
    const pemSecretName = `${prefix}_external_secret_${pemSuffix}`;
    logger.info(`Creating secrets for domain ${domain}`, {
      domain,
      secrets: [crtSecretName, pemSecretName],
    });
    await Promise.all([
      this.dockerode.createSecret({
        Name: crtSecretName,
        Data: crt.toString('base64'),
      }),
      this.dockerode.createSecret({
        Name: pemSecretName,
        Data: pem.toString('base64'),
      }),
    ]);
    logger.info(`Successfully created secrets for domain ${domain}`);
    return {
      crtSecretName,
      pemSecretName,
      crtSuffix,
      pemSuffix,
    };
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
        await new Promise((resolve, reject) => {
          child_process.exec(
            `certbot certonly --dns-cloudflare -n --agree-tos ${stagingFlag} -m ${config.email} -d "${domain}" ` +
            ` --dns-cloudflare-credentials=${this.credentialFile}`, {
              shell: '/bin/sh',
            }, (error, stdout, stderr) => {
              if (error) {
                reject(error);
              } else {
                resolve({
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
          secrets.forEach((secret: { SecretName: string; SecretID: string; }) => {
            if (secret.SecretName.endsWith(domainSecrets.crtSuffix)) {
              somethingUpdated = true;
              logger.info(
                `Replacing ${secret.SecretName} with ${domainSecrets.crtSecretName} on service ${serviceName}`,
              );
              delete secret.SecretID;
              secret.SecretName = domainSecrets.crtSecretName;
            }
            if (secret.SecretName.endsWith(domainSecrets.pemSuffix)) {
              somethingUpdated = true;
              logger.info(
                `Replacing ${secret.SecretName} with ${domainSecrets.pemSecretName} on service ${serviceName}`,
              );
              delete secret.SecretID;
              secret.SecretName = domainSecrets.pemSecretName;
            }
          });
          if (somethingUpdated) {
            logger.info(`Applying the modifications, changing service` +
              ` from version ${service.Version.Index} to ${service.Version.Index + 1}...`);
            service.Version.Index += 1;
            service.version = service.Version.Index;
            await this.dockerode.getService(service.ID).update({
              ID: service.ID,
              version: service.Version.Index,
              TaskTemplate: {
                ContainerSpec: service.TaskTemplate.ContainerSpec,
              },
            });
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
    server.get('/health', (req, res) => {
      res.end({
        healthy: true,
        managing: config.domains,
      });
    });
    server.listen(config.port, () => {
      logger.info('listening on port', { port: config.port });
    });
    this.apply();
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
