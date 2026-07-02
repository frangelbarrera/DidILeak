import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DidILeak — LLM history secret scanner",
  description:
    "Scan your ChatGPT, Claude, and Cursor chat history for leaked API keys, tokens, and PII.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-bg text-text">{children}</body>
    </html>
  );
}
