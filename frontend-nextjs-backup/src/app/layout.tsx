import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import ErrorBoundary from "@/components/ErrorBoundary";
import { ToastProvider } from "@/components/Toast";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "ThreatLens - GPU-Powered Threat Modeling",
  description: "Modern web interface for ThreatLens, a GPU-powered threat modeling documentation generator. Analyze repositories and view comprehensive security assessments.",
  keywords: ["threat modeling", "security", "analysis", "GPU", "documentation"],
  authors: [{ name: "ThreatLens Team" }],
  viewport: "width=device-width, initial-scale=1",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased min-h-screen bg-background font-sans`}
      >
        <ToastProvider>
          <ErrorBoundary>
            <div className="relative flex min-h-screen flex-col">
              <main className="flex-1">
                {children}
              </main>
            </div>
          </ErrorBoundary>
        </ToastProvider>
      </body>
    </html>
  );
}
