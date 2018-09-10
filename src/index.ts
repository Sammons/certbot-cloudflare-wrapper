import 'source-map-support/register';
import { App } from './app';
import { logger } from './logging';
logger.info('starting');
new App().run().catch((e) => {
  logger.error(e);
  process.nextTick(process.exit, 1);
});
