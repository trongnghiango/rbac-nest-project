import { Provider, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as path from 'path';
import * as fs from 'fs';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const Piscina = require('piscina');

export const PISCINA_POOL = 'PISCINA_POOL';

export const PiscinaProvider: Provider = {
  provide: PISCINA_POOL,
  useFactory: (config: ConfigService) => {
    const logger = new Logger('PiscinaProvider');
    const isProduction = process.env.NODE_ENV === 'production';

    // 1. Xác định gốc dự án (Root)
    const projectRoot = process.cwd();

    // 2. Xác định đường dẫn tương đối của worker file trong source
    const workerRelativePath =
      'src/modules/dental/infrastructure/workers/conversion.worker';

    let workerPath: string;

    if (isProduction) {
      // PRODUCTION: Tìm trong folder 'dist'
      // NestJS build structure: dist/src/... hoặc dist/... (nếu config rootDir)
      // Check 1: dist/src/...
      const prodPath1 = path.join(
        projectRoot,
        'dist',
        workerRelativePath + '.js',
      );
      // Check 2: dist/... (loại bỏ 'src' prefix nếu flatten)
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
        // Fallback khẩn cấp: Thử tìm ngay tại __dirname (nếu file provider và worker nằm cạnh nhau sau build)
        workerPath = path.join(__dirname, 'conversion.worker.js');
      }
    } else {
      // DEVELOPMENT: Tìm trong folder 'src' (ts-node)
      workerPath = path.join(projectRoot, workerRelativePath + '.ts');
    }

    if (!fs.existsSync(workerPath)) {
      logger.error(
        `CRITICAL: Worker file not found at calculated path: ${workerPath}`,
      );
      // Thử list thư mục để debug nếu lỗi
      logger.error(`Dirname content: ${fs.readdirSync(__dirname)}`);
      throw new Error(`Worker file not found: ${workerPath}`);
    }

    logger.log(`🏊 Initializing Piscina with worker: ${workerPath}`);

    return new Piscina({
      filename: workerPath,
      minThreads: config.get('dental.minThreads'),
      maxThreads: config.get('dental.maxThreads'),
      // Chỉ dùng ts-node loader khi chạy file .ts
      execArgv: workerPath.endsWith('.ts') ? ['-r', 'ts-node/register'] : [],
    });
  },
  inject: [ConfigService],
};
