/**
 * Centralized Winston Logger Configuration
 * 
 * Sends logs to the central log server (PDF processing app) via HTTP
 * Falls back to local console/file logging if the central server is unavailable
 */

import winston from 'winston';
import TransportStream from 'winston-transport';
import axios from 'axios';

// Custom HTTP Transport for sending logs to central server
class HTTPLogTransport extends TransportStream {
    private apiUrl: string;
    private bearerToken: string;
    private retryAttempts: number = 3;
    private retryDelay: number = 1000; // 1 second

    constructor(opts: winston.transport.TransportStreamOptions & { apiUrl: string; bearerToken: string }) {
        super(opts);
        this.apiUrl = opts.apiUrl;
        this.bearerToken = opts.bearerToken;
    }

    async log(info: any, callback: () => void) {
        setImmediate(() => {
            this.emit('logged', info);
        });

        // Format log entry for central server
        const logEntry = {
            timestamp: info.timestamp || new Date().toISOString(),
            level: info.level.toUpperCase(),
            service: 'nodejs-app',
            message: info.message,
            context: info.context || {},
            error: info.error || (info.stack ? {
                type: info.error?.name || 'Error',
                message: info.error?.message || info.message,
                stack: info.stack
            } : undefined)
        };

        // Send to central log server with retry logic
        this.sendLog(logEntry, 0);

        callback();
    }

    private async sendLog(logEntry: any, attempt: number) {
        try {
            await axios.post(this.apiUrl, logEntry, {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.bearerToken}`
                },
                timeout: 5000 // 5 second timeout
            });
        } catch (error: any) {
            // Retry logic
            if (attempt < this.retryAttempts) {
                setTimeout(() => {
                    this.sendLog(logEntry, attempt + 1);
                }, this.retryDelay * (attempt + 1)); // Exponential backoff
            } else {
                // Log to console on final failure (local fallback)
                console.error('Failed to send log to central server after retries:', {
                    error: error.message,
                    logEntry
                });
            }
        }
    }
}

// Get environment variables
const LOG_API_URL = process.env.LOG_API_URL || '';
const LOG_API_BEARER_TOKEN = process.env.LOG_API_BEARER_TOKEN || '';

// Create Winston logger instance
const logger = winston.createLogger({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'nodejs-app' },
    transports: []
});

// Add HTTP transport if configured
if (LOG_API_URL && LOG_API_BEARER_TOKEN) {
    logger.add(new HTTPLogTransport({
        apiUrl: LOG_API_URL,
        bearerToken: LOG_API_BEARER_TOKEN
    }));
    console.log('📡 Central logging enabled:', LOG_API_URL);
} else {
    console.warn('⚠️  Central logging not configured. Set LOG_API_URL and LOG_API_BEARER_TOKEN in .env.local');
}

// Always add console transport for local development
logger.add(new winston.transports.Console({
    format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ level, message, timestamp, service, context }) => {
            const contextStr = context && Object.keys(context).length > 0
                ? ` ${JSON.stringify(context)}`
                : '';
            return `${timestamp} [${service}] ${level}: ${message}${contextStr}`;
        })
    )
}));

// Optional: Add local file transport as backup
if (process.env.NODE_ENV === 'production') {
    logger.add(new winston.transports.File({
        filename: 'logs/error.log',
        level: 'error'
    }));
    logger.add(new winston.transports.File({
        filename: 'logs/combined.log'
    }));
}

/**
 * Helper function to log with context
 * 
 * @example
 * logWithContext('info', 'User logged in', { userId: '123', ip: '192.168.1.1' });
 */
export function logWithContext(
    level: 'debug' | 'info' | 'warn' | 'error',
    message: string,
    context?: Record<string, any>,
    error?: Error
) {
    logger.log({
        level,
        message,
        context,
        error: error ? {
            type: error.name,
            message: error.message,
            stack: error.stack
        } : undefined
    });
}

/**
 * Log an error with full stack trace and context
 */
export function logError(message: string, error: Error, context?: Record<string, any>) {
    logWithContext('error', message, context, error);
}

/**
 * Log an info message with context
 */
export function logInfo(message: string, context?: Record<string, any>) {
    logWithContext('info', message, context);
}

/**
 * Log a warning with context
 */
export function logWarn(message: string, context?: Record<string, any>) {
    logWithContext('warn', message, context);
}

/**
 * Log debug information with context
 */
export function logDebug(message: string, context?: Record<string, any>) {
    logWithContext('debug', message, context);
}

export default logger;
