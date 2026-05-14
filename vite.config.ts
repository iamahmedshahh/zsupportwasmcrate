import { defineConfig } from 'vitest/config';
import { resolve } from 'path';
import wasm from 'vite-plugin-wasm';

export default defineConfig({
  plugins: [wasm()],
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'veruszsupportlib',
      fileName: 'index',
      formats: ['es'],
    },
    rollupOptions: {
      external: [],
    },
    copyPublicDir: false,
  },
  test: {
    globals: true,
    poolOptions: {
      forks: {
        execArgv: ['--experimental-wasm-modules'],
      },
    },
  },
});