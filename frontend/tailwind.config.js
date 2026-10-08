/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        turnet: {
          bg: "#0b1416",
          panel: "#11201f",
          accent: "#1f7a8c",
          accent2: "#2bb3a3",
          warn: "#d98a2b",
          text: "#d7e3e2",
          muted: "#7d9492",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
