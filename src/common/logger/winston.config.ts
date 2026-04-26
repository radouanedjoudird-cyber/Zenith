import { utilities as nestWinstonModuleUtilities } from 'nest-winston';
import * as winston from 'winston';
import 'winston-daily-rotate-file';

/**
 * ZENITH ADVANCED LOGGING ARCHITECTURE
 * -------------------------------------
 * STRATEGY: 
 * 1. Persistent Storage: Daily rotation to prevent disk exhaustion.
 * 2. Severity Isolation: Dedicated logs for security threats.
 * 3. High Performance: Asynchronous file writing via winston-daily-rotate-file.
 */
export const winstonConfig = {
  transports: [
    // CONSOLE: Real-time, colorized logs for the developer terminal
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.ms(),
        nestWinstonModuleUtilities.format.nestLike('Zenith', {
          colors: true,
          prettyPrint: true,
        }),
      ),
    }),
    
    // SECURITY LOGS: Forensic record of unauthorized attempts (Warn/Error)
    new winston.transports.DailyRotateFile({
      filename: 'logs/security-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d',
      level: 'warn',
    }),

    // COMBINED LOGS: Full system operational history
    new winston.transports.DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
    }),
  ],
};