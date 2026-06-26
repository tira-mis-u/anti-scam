/**
 * Backend Logger – chuẩn hoá log với timestamp, level và context.
 */
const LOG_LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const CURRENT_LOG_LEVEL = LOG_LEVELS[process.env.LOG_LEVEL || 'info'] ?? 2;

function formatLog(level, context, message, extra) {
    const ts = new Date().toISOString();
    const base = `[${ts}] [${level.toUpperCase()}] [${context}] ${message}`;
    if (extra instanceof Error) {
        return `${base}\n  ${extra.stack || extra.message}`;
    }
    if (extra !== undefined && extra !== null) {
        try { return `${base} ${JSON.stringify(extra)}`; } catch (_) { return base; }
    }
    return base;
}

function log(level, context, message, extra) {
    if (LOG_LEVELS[level] > CURRENT_LOG_LEVEL) return;
    const formatted = formatLog(level, context, message, extra);
    if (level === 'error') console.error(formatted);
    else if (level === 'warn') console.warn(formatted);
    else console.log(formatted);
}

const logger = {
    info: (ctx, msg, extra) => log('info', ctx, msg, extra),
    warn: (ctx, msg, extra) => log('warn', ctx, msg, extra),
    error: (ctx, msg, extra) => log('error', ctx, msg, extra),
    debug: (ctx, msg, extra) => log('debug', ctx, msg, extra),
};

module.exports = { logger };
