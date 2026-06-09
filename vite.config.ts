import { defineConfig } from 'vite';
import { resolve } from 'path';
import wasm from 'vite-plugin-wasm';

export default defineConfig({
  plugins: [wasm()],
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      fileName: (format) => `index.${format}.js`,
      formats: ['es'],
    },
     rollupOptions: {
      external: [
        'verus-typescript-primitives',
        'bn.js',
        'buffer',
        // also externalize any subpath imports
        /^verus-typescript-primitives\//,
      ],
    },
    copyPublicDir: false,
    assetsInlineLimit: 100_000_000,
  },
});