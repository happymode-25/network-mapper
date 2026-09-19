/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Severity palette from the build spec
        'sev-none': '#2F3E46',
        'sev-low': '#2A9D8F',
        'sev-medium': '#E9C46A',
        'sev-high': '#F4A261',
        'sev-critical': '#E76F51',
        midnight: '#1B2430',
      },
    },
  },
  plugins: [],
}