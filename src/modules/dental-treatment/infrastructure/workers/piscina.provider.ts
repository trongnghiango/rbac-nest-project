import { Provider, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as path from 'path';
import * as fs from 'fs';

// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires, @typescript-eslint/no-unsafe-assignment
const Piscina = require('piscina');

export const PISCINA_POOL = 'PISCINA_POOL';

export const PiscinaProvider: Provider = {
  provide: PISCINA_POOL,
  useFactory: (config: ConfigService) => {
    const logger = new Logger('PiscinaProvider');
    const isProduction = process.env.NODE_ENV === 'production';

    const projectRoot = process.cwd();

    const workerRelativePath =
      'src/modules/dental-treatment/infrastructure/workers/conversion.worker';

    let workerPath: string;

    if (isProduction) {
      const prodPath1 = path.join(
        projectRoot,
        'dist',
        workerRelativePath + '.js',
      );
      const prodPath2 = path.join(
        projectRoot,
        'dist',
        workerRelativePath.replace('src/', '') + '.js',
      );

      if (fs.existsSync(prodPath1)) {
        workerPath = prodPath1;
      } else if (fs.existsSync(prodPath2)) {
        workerPath = prodPath2;
      } else {
        workerPath = path.join(__dirname, 'conversion.worker.js');
      }
    } else {
      workerPath = path.join(projectRoot, workerRelativePath + '.ts');
    }

    if (!fs.existsSync(workerPath)) {
      logger.error(
        `CRITICAL: Worker file not found at calculated path: ${workerPath}`,
      );
      const dirContent = fs.readdirSync(__dirname).join(', ');
      logger.error(`Dirname content: [${dirContent}]`);
      throw new Error(`Worker file not found: ${workerPath}`);
    }

    logger.log(`🏊 Initializing Piscina with worker: ${workerPath}`);

    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-return
    return new Piscina({
      filename: workerPath,
      minThreads: config.get<number>('dental.minThreads') || 0,
      maxThreads: config.get<number>('dental.maxThreads') || 4,
      execArgv: workerPath.endsWith('.ts') ? ['-r', 'ts-node/register'] : [],
    });
  },
  inject: [ConfigService],
};
