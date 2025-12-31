import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  async rewrites() {
    return [
      {
        source: '/api/threatwiki/:path*',
        destination: 'http://localhost:8001/:path*'
      }
    ]
  }
};

export default nextConfig;
