import * as child_process from 'child_process';
import * as crypto from 'crypto';
import * as dockerode from 'dockerode';
import * as express from 'express';
import * as _ from 'lodash';
import { config } from './config';
import { logger } from './logging';

export class App {

  get dockerode() {
    return new dockerode({
      socketPath: config.socketPath as string,
    });
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
      const serviceSecrets = _.get(service, 'Spec.TaskTemplate.ContainerSpec.Secrets', []);
      const serviceName = _.get(service, 'Spec.Name');
      logger.info(`Testing service "${serviceName}" to see if affected by domain "${domain}"`);
      return serviceSecrets.some((secret: any) => {
        const serviceSecretId = _.get(secret, 'SecretID');
        return domainSecretIds.has(serviceSecretId);
      });
    });
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
        child_process.execSync(
          `certbot certonly --dns-cloudflare -n --agree-tos -m ${config.email} -d "${domain}"` +
          ` --dns-cloudflare-credentials=$credential_file`,
        );
      } catch (error) {

      }
    }
  }

  public async run() {
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
