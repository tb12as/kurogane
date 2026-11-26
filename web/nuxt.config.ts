import tailwindcss from '@tailwindcss/vite'

// static SPA embedded into the Go binary (web/embed.go serves .output/public)
export default defineNuxtConfig({
  compatibilityDate: '2026-11-01',
  ssr: false,
  devtools: { enabled: false },
  telemetry: false,
  modules: ['shadcn-nuxt'],
  // fonts are bundled into the binary; mono is latin-only because it renders machine values (IPs, keys, paths)
  css: [
    '@fontsource-variable/ibm-plex-sans/wght.css',
    '@fontsource/ibm-plex-mono/latin-400.css',
    '@fontsource/ibm-plex-mono/latin-500.css',
    // font-brand: wordmark, page and card titles, labels and buttons (matches the logo artwork)
    '@fontsource/montserrat/latin-400.css',
    '@fontsource/montserrat/latin-500.css',
    '@fontsource/montserrat/latin-600.css',
    '~/assets/css/main.css',
  ],
  shadcn: { prefix: '', componentDir: './app/components/ui' },
  app: {
    head: {
      title: 'Kurogane',
      htmlAttrs: { lang: 'en' },
      meta: [{ name: 'viewport', content: 'width=device-width, initial-scale=1' }],
      link: [
        {
          rel: 'icon',
          type: 'image/svg+xml',
          media: '(prefers-color-scheme: light)',
          href: '/kurogane-icon-light-aligned.svg',
        },
        {
          rel: 'icon',
          type: 'image/svg+xml',
          media: '(prefers-color-scheme: dark)',
          href: '/kurogane-icon-dark-aligned.svg',
        },
      ],
    },
  },
  experimental: { appManifest: false },
  // only the SPA shell; the Go handler falls back to index.html for client routes
  nitro: { prerender: { crawlLinks: false, routes: ['/'] } },
  vite: {
    plugins: [tailwindcss()],
    // dev: proxy the API to a locally running agent
    server: { proxy: { '/api': { target: process.env.KRGN_API || 'http://127.0.0.1:9443', changeOrigin: true } } },
  },
  typescript: { strict: true },
})
