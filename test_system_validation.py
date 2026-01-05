#!/usr/bin/env python3
"""
ThreatLens System Validation Script

This script performs comprehensive end-to-end testing of the ThreatLens system
to ensure all components work correctly before production deployment.
"""

import sys
import os
import time
import json
import asyncio
import httpx
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

class ThreatLensValidator:
    """Comprehensive system validator for ThreatLens"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.client = httpx.Client(base_url=base_url, timeout=60.0)
        self.test_results = []
        self.server_process = None
    
    def log_test(self, test_name: str, success: bool, message: str, details: Optional[Dict] = None):
        """Log test result"""
        status = "[PASS]" if success else "[FAIL]"
        print(f"{status} {test_name}: {message}")
        
        self.test_results.append({
            "test": test_name,
            "success": success,
            "message": message,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        })
    
    def start_server(self) -> bool:
        """Start the ThreatLens server for testing"""
        print("🚀 Starting ThreatLens server for testing...")
        
        try:
            # Start server in background
            self.server_process = subprocess.Popen([
                sys.executable, "run_server.py"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for server to start
            max_attempts = 30
            for attempt in range(max_attempts):
                try:
                    response = self.client.get("/health")
                    if response.status_code == 200:
                        self.log_test("Server Startup", True, "Server started successfully")
                        return True
                except:
                    pass
                
                time.sleep(2)
                print(f"  Waiting for server... ({attempt + 1}/{max_attempts})")
            
            self.log_test("Server Startup", False, "Server failed to start within timeout")
            return False
            
        except Exception as e:
            self.log_test("Server Startup", False, f"Failed to start server: {e}")
            return False
    
    def stop_server(self):
        """Stop the test server"""
        if self.server_process:
            self.server_process.terminate()
            self.server_process.wait()
            print("🛑 Test server stopped")
    
    def test_environment_setup(self) -> bool:
        """Test 1: Verify environment setup"""
        print("\n📋 Testing Environment Setup...")
        
        success = True
        
        # Check Python version
        if sys.version_info < (3, 8):
            self.log_test("Python Version", False, f"Python 3.8+ required, found {sys.version}")
            success = False
        else:
            self.log_test("Python Version", True, f"Python {sys.version_info.major}.{sys.version_info.minor}")
        
        # Check required files
        required_files = [
            "api/main.py",
            "api/config.py", 
            "api/models.py",
            "api/database.py",
            "api/security_wiki_generator.py",
            "api/rag.py",
            "requirements.txt",
            ".env.example"
        ]
        
        for file_path in required_files:
            if Path(file_path).exists():
                self.log_test(f"File Check: {file_path}", True, "File exists")
            else:
                self.log_test(f"File Check: {file_path}", False, "File missing")
                success = False
        
        # Check environment variables
        env_file = Path(".env")
        if env_file.exists():
            self.log_test("Environment File", True, ".env file exists")
            
            # Check for critical env vars
            with open(env_file) as f:
                env_content = f.read()
                
            critical_vars = ["OPENAI_API_KEY", "LLM_PROVIDER"]
            for var in critical_vars:
                if var in env_content and not env_content.count(f"{var}=your-") > 0:
                    self.log_test(f"Env Var: {var}", True, "Configured")
                else:
                    self.log_test(f"Env Var: {var}", False, "Not configured or using placeholder")
                    success = False
        else:
            self.log_test("Environment File", False, ".env file missing")
            success = False
        
        return success
    
    def test_api_health(self) -> bool:
        """Test 2: API Health Checks"""
        print("\n🏥 Testing API Health...")
        
        success = True
        
        # Basic health check
        try:
            response = self.client.get("/health")
            if response.status_code == 200:
                health_data = response.json()
                self.log_test("Basic Health", True, f"Status: {health_data.get('status')}")
                
                # Check specific health components
                if health_data.get("database_status") == "healthy":
                    self.log_test("Database Health", True, "Database is healthy")
                else:
                    self.log_test("Database Health", False, f"Database status: {health_data.get('database_status')}")
                    success = False
                
                if health_data.get("llm_config_valid"):
                    self.log_test("LLM Config", True, "LLM configuration is valid")
                else:
                    self.log_test("LLM Config", False, "LLM configuration is invalid")
                    success = False
                    
            else:
                self.log_test("Basic Health", False, f"Health check failed: {response.status_code}")
                success = False
                
        except Exception as e:
            self.log_test("Basic Health", False, f"Health check error: {e}")
            success = False
        
        # Resource status check
        try:
            response = self.client.get("/resources")
            if response.status_code == 200:
                resource_data = response.json()
                self.log_test("Resource Status", True, f"Mode: {resource_data.get('processing_mode')}")
            else:
                self.log_test("Resource Status", False, f"Resource check failed: {response.status_code}")
                success = False
        except Exception as e:
            self.log_test("Resource Status", False, f"Resource check error: {e}")
            success = False
        
        return success
    
    def test_repository_validation(self) -> bool:
        """Test 3: Repository Validation"""
        print("\n🔍 Testing Repository Validation...")
        
        success = True
        
        # Test valid GitHub repository
        try:
            response = self.client.post("/validate_repo", json={
                "repo_url": "https://github.com/octocat/Hello-World.git"
            })
            
            if response.status_code == 200:
                result = response.json()
                if result.get("valid"):
                    self.log_test("GitHub Repo Validation", True, "Valid repository detected")
                else:
                    self.log_test("GitHub Repo Validation", False, f"Validation failed: {result.get('message')}")
                    success = False
            else:
                self.log_test("GitHub Repo Validation", False, f"Validation request failed: {response.status_code}")
                success = False
                
        except Exception as e:
            self.log_test("GitHub Repo Validation", False, f"Validation error: {e}")
            success = False
        
        # Test invalid repository
        try:
            response = self.client.post("/validate_repo", json={
                "repo_url": "https://github.com/invalid/nonexistent-repo.git"
            })
            
            if response.status_code == 200:
                result = response.json()
                if not result.get("valid"):
                    self.log_test("Invalid Repo Detection", True, "Invalid repository correctly detected")
                else:
                    self.log_test("Invalid Repo Detection", False, "Invalid repository not detected")
                    success = False
            else:
                self.log_test("Invalid Repo Detection", True, "Invalid repository rejected by server")
                
        except Exception as e:
            self.log_test("Invalid Repo Detection", False, f"Invalid repo test error: {e}")
            success = False
        
        return success
    
    def test_database_operations(self) -> bool:
        """Test 4: Database Operations"""
        print("\n🗄️ Testing Database Operations...")
        
        success = True
        
        # Database health
        try:
            response = self.client.get("/database/health")
            if response.status_code == 200:
                db_health = response.json()
                self.log_test("Database Health", True, f"Status: {db_health.get('status')}")
            else:
                self.log_test("Database Health", False, f"Database health check failed: {response.status_code}")
                success = False
        except Exception as e:
            self.log_test("Database Health", False, f"Database health error: {e}")
            success = False
        
        # Database statistics
        try:
            response = self.client.get("/database/statistics")
            if response.status_code == 200:
                stats = response.json()
                self.log_test("Database Statistics", True, f"Schema version: {stats.get('schema_version')}")
            else:
                self.log_test("Database Statistics", False, f"Statistics failed: {response.status_code}")
                success = False
        except Exception as e:
            self.log_test("Database Statistics", False, f"Statistics error: {e}")
            success = False
        
        return success
    
    def test_repository_analysis_workflow(self) -> bool:
        """Test 5: Repository Analysis Workflow (Mock)"""
        print("\n🔬 Testing Repository Analysis Workflow...")
        
        success = True
        
        # Test repository status check (should return no analysis)
        try:
            response = self.client.get("/repo_status/test-repo")
            if response.status_code == 200:
                status = response.json()
                if not status.get("exists"):
                    self.log_test("Repo Status Check", True, "No existing analysis found (expected)")
                else:
                    self.log_test("Repo Status Check", True, "Existing analysis found")
            else:
                self.log_test("Repo Status Check", False, f"Status check failed: {response.status_code}")
                success = False
        except Exception as e:
            self.log_test("Repo Status Check", False, f"Status check error: {e}")
            success = False
        
        # Test analysis queue status
        try:
            response = self.client.get("/system/queue")
            if response.status_code == 200:
                queue_status = response.json()
                self.log_test("Analysis Queue", True, f"Queue size: {queue_status.get('queue_size', 0)}")
            else:
                self.log_test("Analysis Queue", False, f"Queue check failed: {response.status_code}")
                success = False
        except Exception as e:
            self.log_test("Analysis Queue", False, f"Queue check error: {e}")
            success = False
        
        return success
    
    def test_error_handling(self) -> bool:
        """Test 6: Error Handling"""
        print("\n⚠️ Testing Error Handling...")
        
        success = True
        
        # Test invalid endpoint
        try:
            response = self.client.get("/nonexistent-endpoint")
            if response.status_code == 404:
                self.log_test("404 Handling", True, "404 error properly returned")
            else:
                self.log_test("404 Handling", False, f"Unexpected status: {response.status_code}")
                success = False
        except Exception as e:
            self.log_test("404 Handling", False, f"404 test error: {e}")
            success = False
        
        # Test invalid request body
        try:
            response = self.client.post("/validate_repo", json={
                "invalid_field": "invalid_value"
            })
            if response.status_code in [400, 422]:
                self.log_test("Validation Error Handling", True, "Invalid request properly rejected")
            else:
                self.log_test("Validation Error Handling", False, f"Unexpected status: {response.status_code}")
                success = False
        except Exception as e:
            self.log_test("Validation Error Handling", False, f"Validation test error: {e}")
            success = False
        
        return success
    
    def test_configuration_management(self) -> bool:
        """Test 7: Configuration Management"""
        print("\n⚙️ Testing Configuration Management...")
        
        success = True
        
        # Configuration summary
        try:
            response = self.client.get("/config/summary")
            if response.status_code == 200:
                config = response.json()
                self.log_test("Config Summary", True, f"LLM Provider: {config.get('llm_provider')}")
            else:
                self.log_test("Config Summary", False, f"Config summary failed: {response.status_code}")
                success = False
        except Exception as e:
            self.log_test("Config Summary", False, f"Config summary error: {e}")
            success = False
        
        # Configuration validation
        try:
            response = self.client.get("/config/validate")
            if response.status_code == 200:
                validation = response.json()
                if validation.get("valid"):
                    self.log_test("Config Validation", True, "Configuration is valid")
                else:
                    self.log_test("Config Validation", False, "Configuration validation failed")
                    success = False
            else:
                self.log_test("Config Validation", False, f"Config validation failed: {response.status_code}")
                success = False
        except Exception as e:
            self.log_test("Config Validation", False, f"Config validation error: {e}")
            success = False
        
        return success
    
    def run_all_tests(self) -> bool:
        """Run all validation tests"""
        print("🧪 ThreatLens System Validation")
        print("=" * 50)
        
        # Start server
        if not self.start_server():
            return False
        
        try:
            # Run all tests
            tests = [
                ("Environment Setup", self.test_environment_setup),
                ("API Health", self.test_api_health),
                ("Repository Validation", self.test_repository_validation),
                ("Database Operations", self.test_database_operations),
                ("Analysis Workflow", self.test_repository_analysis_workflow),
                ("Error Handling", self.test_error_handling),
                ("Configuration Management", self.test_configuration_management)
            ]
            
            all_passed = True
            for test_name, test_func in tests:
                try:
                    result = test_func()
                    if not result:
                        all_passed = False
                except Exception as e:
                    self.log_test(test_name, False, f"Test execution error: {e}")
                    all_passed = False
            
            # Summary
            print("\n" + "=" * 50)
            print("📊 Test Summary")
            print("=" * 50)
            
            passed = sum(1 for r in self.test_results if r["success"])
            total = len(self.test_results)
            
            print(f"Total Tests: {total}")
            print(f"Passed: {passed}")
            print(f"Failed: {total - passed}")
            print(f"Success Rate: {(passed/total)*100:.1f}%")
            
            if all_passed:
                print("\n🎉 All tests passed! ThreatLens is ready for production.")
            else:
                print("\n❌ Some tests failed. Please review the issues above.")
                
                # Show failed tests
                failed_tests = [r for r in self.test_results if not r["success"]]
                if failed_tests:
                    print("\n🔍 Failed Tests:")
                    for test in failed_tests:
                        print(f"  - {test['test']}: {test['message']}")
            
            return all_passed
            
        finally:
            self.stop_server()
    
    def save_results(self, filename: str = "validation_results.json"):
        """Save test results to file"""
        with open(filename, 'w') as f:
            json.dump({
                "validation_timestamp": datetime.now().isoformat(),
                "total_tests": len(self.test_results),
                "passed_tests": sum(1 for r in self.test_results if r["success"]),
                "failed_tests": sum(1 for r in self.test_results if not r["success"]),
                "results": self.test_results
            }, f, indent=2)
        print(f"\n💾 Results saved to {filename}")

def main():
    """Main validation function"""
    validator = ThreatLensValidator()
    
    try:
        success = validator.run_all_tests()
        validator.save_results()
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n⏹️ Validation interrupted by user")
        return 1
    except Exception as e:
        print(f"\n💥 Validation failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())