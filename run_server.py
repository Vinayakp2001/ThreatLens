#!/usr/bin/env python3
"""
ThreatLens Server Entry Point
Run this script to start the ThreatLens threat modeling server.
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Now import and run the main application
if __name__ == "__main__":
    from api.main import app
    import uvicorn
    
    print("🚀 Starting ThreatLens GPU-Powered Threat Modeling Server...")
    print("🎮 GPU-accelerated embeddings enabled!")
    print("📊 Access the API at: http://localhost:8000")
    print("📖 API docs at: http://localhost:8000/docs")
    
    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            reload=False,  # Disable reload to avoid import issues
            log_level="info"
        )
    except Exception as e:
        print(f"❌ Server failed to start: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)