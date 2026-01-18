import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';

export default defineConfig({
  site: 'https://0xl0w3.com',
  integrations: [mdx()],
  markdown: {
    shikiConfig: {
      theme: 'github-dark',
      wrap: true
    }
  }
});
