/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0B0F19',
          surface: '#111827',
          elevated: '#1A2234',
          card: '#131B2E',
          border: '#1F293D',
          hover: '#1E293B',
          muted: '#64748B',
          text: '#F1F5F9',
          subtext: '#94A3B8',
        },
        sentinel: {
          cyan: '#06B6D4',
          teal: '#14B8A6',
          blue: '#3B82F6',
          indigo: '#6366F1',
          purple: '#8B5CF6',
        },
        severity: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#EAB308',
          low: '#10B981',
          info: '#3B82F6',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Consolas', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 12s linear infinite',
      }
    },
  },
  plugins: [],
}
