import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// The console is served by the instance, from the same origin as its API.
// The dev server proxies `/api` to a running instance so the page and the API
// are same-origin there too, which is what the instance's own rule asks for:
// a request to the API is only answered when it was addressed to a loopback
// host.
//
// `changeOrigin` stays off on purpose. The instance checks the `Host` header
// it is given, and rewriting it to the target's host would make the check
// meaningless.
export default defineConfig({
  plugins: [vue()],

  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: process.env.NEXAPIPE_ADMIN ?? 'http://127.0.0.1:8080',
        changeOrigin: false,
      },
    },
  },

  build: {
    outDir: 'dist',
    // A fixed name so the instance can serve the bundle from a directory
    // without having to know how the bundler named its assets.
    assetsDir: 'assets',
  },
});
