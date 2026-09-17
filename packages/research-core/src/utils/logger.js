const fs = require('fs');
const path = require('path');
const config = require('./config');

const logDir = path.dirname(config.logging.file);
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

function createLogEntry({ input, status, violationType, threatCategory, confidence, reasoning, action }) {
  return {
    timestamp: new Date().toISOString(),
    input: input ? input.substring(0, 500) : '',
    status,
    violationType: violationType || 'none',
    threatCategory: threatCategory || 'none',
    confidence: confidence || 'n/a',
    reasoning: reasoning || '',
    action,
  };
}

function log(entry) {
  const line = JSON.stringify(entry) + '\n';

  try {
    fs.appendFileSync(config.logging.file, line);
  } catch (err) {
    console.error('[Logger] Failed to write to log file:', err.message);
  }

  if (config.logging.verbose) {
    console.log('[LOG]', JSON.stringify(entry, null, 2));
  }
}

function logSecurity(details) {
  const entry = createLogEntry(details);
  log(entry);
  return entry;
}

module.exports = { logSecurity, createLogEntry };
