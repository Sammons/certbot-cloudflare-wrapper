import * as logging from 'sammons-logger';

const factory = new logging.StaticLogger().logSimpleToStdOut().logToFile({
  path: `${process.cwd()}/logs/log`,
  level: 'debug',
  rotateAfterSizeMb: 0.5,
});

const exp = new class {
  get logger() {
    return factory.nestedMake(1);
  }
}();

export = exp;
