import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Warm terracotta background (Anthropic-inspired)
        bg: "#d97757",
        "bg-deep": "#c66a4c",
        // Cream cards floating on top
        card: "#faf6f0",
        "card-soft": "#f3ede3",
        "card-hover": "#ede5d8",
        // Warm borders
        border: "#e8dfd0",
        "border-soft": "#efe7d8",
        // Text on cream cards
        text: "#2a2622",
        "text-dim": "#6b6660",
        "text-faint": "#9a9388",
        "text-mute": "#b8b0a3",
        // Text on terracotta background
        "on-bg": "#faf6f0",
        "on-bg-dim": "#f0e4d4",
        "on-bg-faint": "#e0d4c0",
        ok: "#5c7a52",
        // Vintage muted severity colors (pixel squares)
        "sev-critical": "#a83232",
        "sev-high": "#c2410c",
        "sev-medium": "#b45309",
        "sev-low": "#3b5e7e",
        "sev-info": "#6b6660",
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "'SF Mono'", "ui-monospace", "Menlo", "monospace"],
        sans: ["'Inter'", "-apple-system", "BlinkMacSystemFont", "'Segoe UI'", "Roboto", "sans-serif"],
      },
      borderRadius: {
        "pixel": "1px",
        "sm2": "6px",
        "md2": "10px",
        "lg2": "14px",
      },
      boxShadow: {
        "soft-sm": "0 1px 2px rgba(42,38,34,0.04)",
        "soft-md": "0 1px 3px rgba(42,38,34,0.05), 0 4px 16px rgba(42,38,34,0.06)",
        "soft-lg": "0 2px 8px rgba(42,38,34,0.08), 0 12px 40px rgba(42,38,34,0.10)",
      },
    },
  },
  plugins: [],
};
export default config;
