#!/usr/bin/env python3
"""
ThreatLens System Testing Script
Tests all components before running full analysis
"""
import requests
import json
import time
import sys
from typing import Dict, Any, List, Tuple

class ThreatLensSystemTester:
    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self.results = []
        
    def log_test(self, test_name: str, success: bool, details: str = "", duration: float = 0):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name} ({duration:.2f}s)")
        if details:
            print(f"   {details}")
        
        self.results.append({
            "test": test_name,
            "success": success,
            "details": details,
            "duration": duration
        })
    
    def test_basic_connectivity(self) -> bool:
        """Test if the server is running"""
        print("\n🔌 Testing Basic Connectivity...")
        start_time = time.time()
        
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                health_data = response.json()
                details = f"Status: {health_data.get('status', 'unknown')}"
                self.log_test("Server Connectivity", True, details, duration)
                return True
            else:
                self.log_test("Server Connectivity", False, f"HTTP {response.status_code}", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test("Server Connectivity", False, str(e), duration)
            return False
    
    def test_system_diagnostics(self) -> bool:
        """Test system diagnostics endpoint"""
        print("\n🔍 Testing System Diagnostics...")
        start_time = time.time()
        
        try:
            response = requests.get(f"{self.base_url}/diagnostics", timeout=30)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                diag_data = response.json()
                details = f"Components: {len(diag_data.get('components', {}))}"
                self.log_test("System Diagnostics", True, details, duration)
                return True
            else:
                self.log_test("System Diagnostics", False, f"HTTP {response.status_code}", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test("System Diagnostics", False, str(e), duration)
            return False
    
    def test_resource_status(self) -> bool:
        """Test resource monitoring"""
        print("\n💻 Testing Resource Status...")
        start_time = time.time()
        
        try:
            response = requests.get(f"{self.base_url}/resources", timeout=15)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                resource_data = response.json()
                gpu_status = "GPU" if resource_data.get("system_capabilities", {}).get("has_gpu") else "CPU"
                details = f"Mode: {resource_data.get('processing_mode', 'unknown')}, {gpu_status}"
                self.log_test("Resource Status", True, details, duration)
                return True
            else:
                self.log_test("Resource Status", False, f"HTTP {response.status_code}", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test("Resource Status", False, str(e), duration)
            return False
    
    def test_llm_connection(self) -> bool:
        """Test LLM provider connection"""
        print("\n🤖 Testing LLM Connection...")
        start_time = time.time()
        
        try:
            response = requests.post(f"{self.base_url}/config/test", timeout=30)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                config_data = response.json()
                llm_test = config_data.get("tests", {}).get("llm_connection", {})
                llm_success = llm_test.get("success", False)
                details = f"LLM Status: {'healthy' if llm_success else 'failed'}"
                if not llm_success and "error" in llm_test:
                    details += f" - {llm_test['error']}"
                self.log_test("LLM Connection", llm_success, details, duration)
                return llm_success
            else:
                self.log_test("LLM Connection", False, f"HTTP {response.status_code}", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test("LLM Connection", False, str(e), duration)
            return False
    
    def test_repository_validation(self) -> bool:
        """Test repository validation"""
        print("\n📁 Testing Repository Validation...")
        start_time = time.time()
        
        # Test with a small, public repository
        test_repo = "https://github.com/octocat/Hello-World"
        
        try:
            response = requests.post(
                f"{self.base_url}/validate_repo",
                json={"repo_url": test_repo},
                timeout=30
            )
            duration = time.time() - start_time
            
            if response.status_code == 200:
                validation_data = response.json()
                is_valid = validation_data.get("valid", False)
                details = f"Repo: {test_repo}, Valid: {is_valid}"
                self.log_test("Repository Validation", is_valid, details, duration)
                return is_valid
            else:
                self.log_test("Repository Validation", False, f"HTTP {response.status_code}", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test("Repository Validation", False, str(e), duration)
            return False
    
    def test_database_connection(self) -> bool:
        """Test database connectivity through health endpoint"""
        print("\n🗄️ Testing Database Connection...")
        start_time = time.time()
        
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                health_data = response.json()
                db_status = health_data.get("database_status", "unknown")
                details = f"Database: {db_status}"
                self.log_test("Database Connection", db_status == "healthy", details, duration)
                return db_status == "healthy"
            else:
                self.log_test("Database Connection", False, f"HTTP {response.status_code}", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test("Database Connection", False, str(e), duration)
            return False
    
    def run_all_tests(self) -> bool:
        """Run all system tests"""
        print("🚀 ThreatLens System Testing")
        print("=" * 50)
        
        tests = [
            self.test_basic_connectivity,
            self.test_system_diagnostics,
            self.test_resource_status,
            self.test_database_connection,
            self.test_llm_connection,
            self.test_repository_validation,
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            if test():
                passed += 1
        
        print("\n" + "=" * 50)
        print(f"📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All systems operational! Ready for repository analysis.")
            return True
        else:
            print("⚠️  Some tests failed. Check the issues above before proceeding.")
            return False
    
    def print_summary(self):
        """Print detailed test summary"""
        print("\n📋 Detailed Test Summary:")
        print("-" * 50)
        
        for result in self.results:
            status = "✅" if result["success"] else "❌"
            print(f"{status} {result['test']}: {result['duration']:.2f}s")
            if result["details"]:
                print(f"   └─ {result['details']}")

def main():
    """Main testing function"""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://127.0.0.1:8000"
    
    tester = ThreatLensSystemTester(base_url)
    
    try:
        success = tester.run_all_tests()
        tester.print_summary()
        
        if success:
            print("\n🚀 System is ready! You can now safely run repository analysis.")
            sys.exit(0)
        else:
            print("\n❌ System has issues. Please fix them before proceeding.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⏹️  Testing interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Testing failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()