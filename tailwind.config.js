/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './App.tsx', './index.tsx', './components/**/*.tsx'],
  theme: {
          extend: {
            colors: {
              'hacker-green': '#00ff41',
              'hacker-green-dark': '#008f11',
              'cyber-blue': '#00bfff',
              'hacker-dark': '#0d0d0d',
              'hacker-dark-2': '#1a1a1a',
              'hacker-red': '#ff0033',
              'text-primary': '#e5e7eb',
              'text-secondary': '#9ca3af',
            },
            fontFamily: {
              mono: ['ui-monospace', 'Menlo', 'Monaco', 'Cascadia Mono', 'Segoe UI Mono', 'Roboto Mono', 'Oxygen Mono', 'Ubuntu Monospace', 'Source Code Pro', 'Fira Mono', 'Droid Sans Mono', 'Courier New', 'monospace'],
            },
            boxShadow: {
              'glow-green': '0 0 5px #00ff41, 0 0 10px #00ff41, 0 0 15px #00ff41',
              'glow-blue': '0 0 5px #00bfff, 0 0 10px #00bfff',
              'glow-red': '0 0 5px #ff0033, 0 0 10px #ff0033',
            },
            keyframes: {
              blink: {
                '0%, 100%': { opacity: 1 },
                '50%': { opacity: 0 },
              },
              fadeIn: {
                'from': { opacity: 0, transform: 'translateY(10px)' },
                'to': { opacity: 1, transform: 'translateY(0)' },
              },
              bounce: {
                '0%, 100%': { transform: 'translateY(-25%)', animationTimingFunction: 'cubic-bezier(0.8, 0, 1, 1)' },
                '50%': { transform: 'translateY(0)', animationTimingFunction: 'cubic-bezier(0, 0, 0.2, 1)' }
              }
            },
            animation: {
              blink: 'blink 1s step-end infinite',
              'fade-in': 'fadeIn 0.5s ease-out forwards',
              'bounce': 'bounce 1s infinite',
            }
          },
        },
  plugins: [],
};
