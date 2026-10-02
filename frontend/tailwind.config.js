/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: "#F8F7F3",
        paper: "#FFFFFF",
        ink: "#0B0E14",
        "ink-soft": "#3A3F4B",
        border: "#E7E4DC",
        accent: {
          indigo: "#6366F1",
          purple: "#A855F7",
          pink: "#EC4899",
        },
        safe: "#16A34A",
        danger: "#DC2626",
        intro: "#0E4F5C",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        display: ["Manrope", "Inter", "system-ui", "sans-serif"],
      },
      keyframes: {
        marquee: {
          "0%": { transform: "translateX(0)" },
          "100%": { transform: "translateX(-50%)" },
        },
        fadeIn: {
          "0%": { opacity: 0, transform: "translateY(6px)" },
          "100%": { opacity: 1, transform: "translateY(0)" },
        },
      },
      animation: {
        marquee: "marquee 28s linear infinite",
        fadeIn: "fadeIn 0.4s ease",
      },
    },
  },
  plugins: [],
}
