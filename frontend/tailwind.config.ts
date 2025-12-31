import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Threat severity colors
        threat: {
          critical: "#dc2626", // red-600
          high: "#ea580c",     // orange-600
          medium: "#d97706",   // amber-600
          low: "#65a30d",      // lime-600
          info: "#2563eb",     // blue-600
        },
        // Status colors
        status: {
          success: "#16a34a",  // green-600
          warning: "#ca8a04",  // yellow-600
          error: "#dc2626",    // red-600
          info: "#2563eb",     // blue-600
        }
      },
      fontFamily: {
        sans: ["system-ui", "sans-serif"],
        mono: ["Consolas", "monospace"],
      },
      animation: {
        "fade-in": "fadeIn 0.5s ease-in-out",
        "slide-in": "slideIn 0.3s ease-out",
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideIn: {
          "0%": { transform: "translateY(-10px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
      },
    },
  },
  plugins: [],
};

export default config;