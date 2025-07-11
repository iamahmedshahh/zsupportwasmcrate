import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
   build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        content: 'src/content.ts',
        inject: 'src/inject.ts',
      },
      output: {
        entryFileNames: `[name].js`,
        assetFileNames: `[name].[ext]`,
        chunkFileNames: `[name].js`,
      },
    },
}
})