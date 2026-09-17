const { execute, parseCommand } = require('../packages/research-core/src/agents/chatbotAgent');

describe('chatbotAgent', () => {
  describe('parseCommand', () => {
    test('parses simple command', () => {
      expect(parseCommand('ls')).toEqual({ binary: 'ls', args: [] });
    });

    test('parses command with args', () => {
      expect(parseCommand('ls -la /tmp')).toEqual({ binary: 'ls', args: ['-la', '/tmp'] });
    });

    test('parses date with format', () => {
      expect(parseCommand('date +%Y-%m-%d')).toEqual({ binary: 'date', args: ['+%Y-%m-%d'] });
    });
  });

  describe('execute', () => {
    test('executes ls successfully', async () => {
      const result = await execute('ls');
      expect(result.success).toBe(true);
      expect(result.output.length).toBeGreaterThan(0);
    });

    test('executes date successfully', async () => {
      const result = await execute('date');
      expect(result.success).toBe(true);
      expect(result.output.length).toBeGreaterThan(0);
    });

    test('executes ls -la successfully', async () => {
      const result = await execute('ls -la');
      expect(result.success).toBe(true);
      expect(result.output).toContain('total');
    });

    test('blocks forbidden commands (defense in depth)', async () => {
      const result = await execute('rm -rf /tmp/test');
      expect(result.success).toBe(false);
      expect(result.error).toContain('not allowed');
    });

    test('blocks cat (defense in depth)', async () => {
      const result = await execute('cat /etc/passwd');
      expect(result.success).toBe(false);
      expect(result.error).toContain('not allowed');
    });

    test('handles ls on non-existent directory', async () => {
      const result = await execute('ls /nonexistent_dir_xyz');
      expect(result.success).toBe(false);
    });
  });
});
