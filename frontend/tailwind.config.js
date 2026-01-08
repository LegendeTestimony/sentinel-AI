/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'sentinel-bg': '#0a0a0a',
        'sentinel-card': '#1a1a1a',
        'sentinel-border': '#2a2a2a',
        'threat-critical': '#ff0000',
        'threat-high': '#ff6600',
        'threat-medium': '#ffaa00',
        'threat-low': '#00ff00',
        'threat-safe': '#00d4ff',
      },
      fontFamily: {
        'sans': ['Inter', 'system-ui', 'sans-serif'],
        'mono': ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
