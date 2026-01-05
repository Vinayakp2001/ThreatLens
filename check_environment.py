#!/usr/bin/env python3
"""
ThreatLens Environment Checker

Quick script to verify that the environment is properly set up
before running the full system validation.
"""

import sys
import os
import subprocess
from pathlib import Path
from typing import List, Tuple

def check_python_version() -> Tuple[bool, str]:
    """Check Python version"""
    if sys.version_info >= (3, 8):
        return True, f"✓ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    else:
        return False, f"✗ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} (3.8+ required)"

def check_dependencies() -> Tuple[bool, List[str]]:
    """Check if required Python packages are installed"""
    # Package name -> import name mapping
    required_packages = {
        "fastapi": "fastapi",
        "uvicorn": "uvicorn", 
        "pydantic": "pydantic",
        "httpx": "httpx",
        "openai": "openai",
        "sentence-transformers": "sentence_transformers",
        "faiss-cpu": "faiss",  # faiss-cpu imports as 'faiss'
        "numpy": "numpy",
        "sqlite3": "sqlite3"  # Built-in
    }
    
    missing = []
    messages = []
    
    for package_name, import_name in required_packages.items():
        try:
            if import_name == "sqlite3":
                import sqlite3
                messages.append(f"✓ {package_name}")
            else:
                __import__(import_name)
                messages.append(f"✓ {package_name}")
        except ImportError:
            missing.append(package_name)
            messages.append(f"✗ {package_name} (missing)")
    
    return len(missing) == 0, messages
    
    return len(missing) == 0, messages

def check_environment_file() -> Tuple[bool, str]:
    """Check if .env file exists and has required variables"""
    env_file = Path(".env")
    
    if not env_file.exists():
        return False, "✗ .env file not found (copy from .env.example)"
    
    with open(env_file) as f:
        content = f.read()
    
    required_vars = ["OPENAI_API_KEY", "LLM_PROVIDER"]
    missing_vars = []
    
    for var in required_vars:
        if var not in content:
            missing_vars.append(var)
        elif f"{var}=your-" in content or f"{var}=" in content and content.split(f"{var}=")[1].split('\n')[0].strip() == "":
            missing_vars.append(f"{var} (not configured)")
    
    if missing_vars:
        return False, f"✗ .env missing/incomplete: {', '.join(missing_vars)}"
    else:
        return True, "✓ .env file configured"

def check_directories() -> Tuple[bool, List[str]]:
    """Check if required directories exist"""
    required_dirs = [
        "api",
        "frontend", 
        "config"
    ]
    
    messages = []
    all_exist = True
    
    for dir_name in required_dirs:
        if Path(dir_name).exists():
            messages.append(f"✓ {dir_name}/")
        else:
            messages.append(f"✗ {dir_name}/ (missing)")
            all_exist = False
    
    return all_exist, messages

def check_critical_files() -> Tuple[bool, List[str]]:
    """Check if critical files exist"""
    critical_files = [
        "api/main.py",
        "api/config.py",
        "api/models.py", 
        "api/database.py",
        "requirements.txt",
        "run_server.py"
    ]
    
    messages = []
    all_exist = True
    
    for file_path in critical_files:
        if Path(file_path).exists():
            messages.append(f"✓ {file_path}")
        else:
            messages.append(f"✗ {file_path} (missing)")
            all_exist = False
    
    return all_exist, messages

def check_node_and_frontend() -> Tuple[bool, str]:
    """Check Node.js and frontend setup"""
    try:
        # Check if Node.js is installed
        result = subprocess.run(["node", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            node_version = result.stdout.strip()
            
            # Check if frontend dependencies are installed
            if Path("frontend/node_modules").exists():
                return True, f"✓ Node.js {node_version} + frontend dependencies"
            else:
                return False, f"✓ Node.js {node_version} but ✗ frontend dependencies not installed"
        else:
            return False, "✗ Node.js not found"
    except FileNotFoundError:
        return False, "✗ Node.js not found"

def detailed_package_check() -> None:
    """Detailed package installation check for debugging"""
    print("\n🔬 Detailed Package Diagnostics:")
    print("-" * 40)
    
    # Check specific packages that commonly have issues
    problematic_packages = [
        ("sentence-transformers", "sentence_transformers"),
        ("faiss-cpu", "faiss"),
        ("torch", "torch")
    ]
    
    for package_name, import_name in problematic_packages:
        try:
            module = __import__(import_name)
            version = getattr(module, '__version__', 'unknown')
            print(f"✓ {package_name} -> {import_name} (v{version})")
        except ImportError as e:
            print(f"✗ {package_name} -> {import_name}: {e}")
            
            # Try to get more info about why it failed
            try:
                import subprocess
                result = subprocess.run([sys.executable, "-m", "pip", "show", package_name], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"  Package {package_name} is installed but import failed")
                    print(f"  Pip info: {result.stdout.split('Version:')[1].split()[0] if 'Version:' in result.stdout else 'unknown'}")
                else:
                    print(f"  Package {package_name} not found in pip list")
            except:
                print(f"  Could not check pip installation status")

def main():
    """Main environment check"""
    print("🔍 ThreatLens Environment Check")
    print("=" * 40)
    
    all_good = True
    
    # Check Python version
    python_ok, python_msg = check_python_version()
    print(f"Python Version: {python_msg}")
    if not python_ok:
        all_good = False
    
    # Check dependencies
    deps_ok, dep_messages = check_dependencies()
    print(f"\nPython Dependencies:")
    for msg in dep_messages:
        print(f"  {msg}")
    if not deps_ok:
        all_good = False
        # Run detailed diagnostics if dependencies failed
        detailed_package_check()
    
    # Check environment file
    env_ok, env_msg = check_environment_file()
    print(f"\nEnvironment: {env_msg}")
    if not env_ok:
        all_good = False
    
    # Check directories
    dirs_ok, dir_messages = check_directories()
    print(f"\nDirectories:")
    for msg in dir_messages:
        print(f"  {msg}")
    if not dirs_ok:
        all_good = False
    
    # Check critical files
    files_ok, file_messages = check_critical_files()
    print(f"\nCritical Files:")
    for msg in file_messages:
        print(f"  {msg}")
    if not files_ok:
        all_good = False
    
    # Check Node.js and frontend
    node_ok, node_msg = check_node_and_frontend()
    print(f"\nFrontend: {node_msg}")
    if not node_ok:
        print("  Note: Frontend is optional for API-only testing")
    
    # Summary
    print("\n" + "=" * 40)
    if all_good:
        print("🎉 Environment check passed!")
        print("✅ Ready to run system validation")
        print("\nNext steps:")
        print("1. Run: python test_system_validation.py")
        print("2. Or start server: python run_server.py")
    else:
        print("❌ Environment check failed!")
        print("🔧 Please fix the issues above before proceeding")
        print("\nCommon fixes:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Copy environment: cp .env.example .env")
        print("3. Configure .env with your API keys")
        if not node_ok:
            print("4. Install Node.js and run: cd frontend && npm install")
        
        if not deps_ok:
            print("\n🔧 Dependency Installation Help:")
            print("Try these commands one by one:")
            print("  pip install sentence-transformers")
            print("  pip install faiss-cpu")
            print("  pip install torch --index-url https://download.pytorch.org/whl/cpu")
    
    return 0 if all_good else 1

if __name__ == "__main__":
    sys.exit(main())