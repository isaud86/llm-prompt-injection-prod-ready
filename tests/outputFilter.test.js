const { filterOutput, sanitizeError } = require('../packages/research-core/src/validators/outputFilter');

describe('outputFilter', () => {
  describe('filterOutput', () => {
    test('passes through normal ls output unchanged', () => {
      const output = 'file1.txt\nfile2.js\ndir1\n';
      expect(filterOutput(output)).toBe(output);
    });

    test('redacts password hashes', () => {
      const output = 'root:$6$abc123def456:18000:0:99999:7:::';
      const filtered = filterOutput(output);
      expect(filtered).toContain('[REDACTED_HASH]');
      expect(filtered).not.toContain('$6$abc123def456');
    });

    test('redacts private keys', () => {
      const output = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...\n-----END RSA PRIVATE KEY-----';
      const filtered = filterOutput(output);
      expect(filtered).toContain('[REDACTED_PRIVATE_KEY]');
    });

    test('redacts internal IP addresses', () => {
      const output = 'server at 192.168.1.100 is running';
      const filtered = filterOutput(output);
      expect(filtered).toContain('[REDACTED_IP]');
      expect(filtered).not.toContain('192.168.1.100');
    });

    test('redacts API key patterns', () => {
      const output = 'api_key=sk_live_abc123def456';
      const filtered = filterOutput(output);
      expect(filtered).toContain('[REDACTED_CREDENTIAL]');
    });

    test('redacts AWS access keys', () => {
      const output = 'AKIAIOSFODNN7EXAMPLE';
      const filtered = filterOutput(output);
      expect(filtered).toContain('[REDACTED_AWS_KEY]');
    });

    test('handles null/empty input', () => {
      expect(filterOutput(null)).toBe('');
      expect(filterOutput('')).toBe('');
      expect(filterOutput(undefined)).toBe('');
    });
  });

  describe('sanitizeError', () => {
    test('passes through safe error messages', () => {
      expect(sanitizeError('No such file or directory')).toContain('No such file or directory');
      expect(sanitizeError('Permission denied')).toContain('Permission denied');
    });

    test('returns generic message for unknown errors', () => {
      const result = sanitizeError('segfault at address 0x7fff5fbff8c8 in /usr/lib/system.dylib');
      expect(result).toBe('An error occurred while processing your request.');
    });

    test('returns generic message for null', () => {
      expect(sanitizeError(null)).toBe('An error occurred while processing your request.');
    });
  });
});
