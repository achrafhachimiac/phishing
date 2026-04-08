import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['backend/**/*.test.ts', 'src/**/*.test.ts', 'src/**/*.test.tsx'],
    pool: 'threads',
    maxWorkers: 1,
    fileParallelism: false,
    setupFiles: ['./src/test/setup.ts'],
    coverage: {
      reporter: ['text', 'html'],
    },
  },
});