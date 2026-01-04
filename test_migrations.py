#!/usr/bin/env python3
"""
Test script for database migrations

This script tests the migration system to ensure it works correctly
with the new SecurityDocument and PRAnalysis models.
"""
import os
import sys
import tempfile
import sqlite3
from datetime import datetime
from pathlib import Path

# Add the api directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'api'))

from migrations import MigrationManager
from database import DatabaseManager
from models import SecurityDocument, PRAnalysis, CodeReference

def test_migration_system():
    """Test the complete migration system"""
    print("Testing Database Migration System")
    print("=" * 40)
    
    # Create temporary database for testing
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
        test_db_path = tmp_db.name
    
    try:
        # Test 1: Initialize fresh database
        print("1. Testing fresh database initialization...")
        manager = MigrationManager(test_db_path)
        
        # Check initial state
        current_version = manager.get_current_version()
        print(f"   Initial version: {current_version}")
        
        # Apply all migrations
        result = manager.apply_migrations()
        if result['success']:
            print(f"   [SUCCESS] Applied {len(result['migrations_applied'])} migrations")
        else:
            print(f"   [ERROR] Migration failed: {result['errors']}")
            return False
        
        # Test 2: Validate migration status
        print("2. Testing migration status...")
        status = manager.get_migration_status()
        if status['up_to_date']:
            print("   [SUCCESS] Database is up to date")
        else:
            print(f"   [ERROR] Database not up to date: {status['pending_migrations']} pending")
            return False
        
        # Test 3: Validate migration integrity
        print("3. Testing migration validation...")
        validation = manager.validate_migrations()
        if validation['valid']:
            print("   [SUCCESS] Migration validation passed")
        else:
            print(f"   [ERROR] Migration validation failed: {validation['errors']}")
            return False
        
        # Test 4: Test database operations with new models
        print("4. Testing new model operations...")
        db_manager = DatabaseManager(test_db_path)
        
        # Test SecurityDocument
        security_doc = SecurityDocument(
            id="test-doc-1",
            repo_id="test-repo",
            title="Test Security Document",
            content="This is a test security document",
            scope="full_repo",
            metadata={"test": "data"},
            code_references=[
                CodeReference(
                    id="ref-1",
                    file_path="test.py",
                    line_start=10,
                    line_end=20,
                    function_name="test_function"
                )
            ]
        )
        
        if db_manager.save_security_document(security_doc):
            print("   [SUCCESS] SecurityDocument save successful")
        else:
            print("   [ERROR] SecurityDocument save failed")
            return False
        
        # Test retrieval
        retrieved_doc = db_manager.get_security_document("test-doc-1")
        if retrieved_doc and retrieved_doc.title == "Test Security Document":
            print("   [SUCCESS] SecurityDocument retrieval successful")
        else:
            print("   [ERROR] SecurityDocument retrieval failed")
            return False
        
        # Test PRAnalysis
        pr_analysis = PRAnalysis(
            id="test-pr-1",
            pr_id="123",
            repo_id="test-repo",
            pr_url="https://github.com/test/repo/pull/123",
            changed_files=["file1.py", "file2.py"],
            security_issues=[{"type": "test", "severity": "low"}],
            recommendations=["Test recommendation"],
            risk_level="low",
            has_repo_context=True,
            context_used={"context": "test"}
        )
        
        if db_manager.save_pr_analysis(pr_analysis):
            print("   [SUCCESS] PRAnalysis save successful")
        else:
            print("   [ERROR] PRAnalysis save failed")
            return False
        
        # Test retrieval
        retrieved_pr = db_manager.get_pr_analysis("123")
        if retrieved_pr and retrieved_pr.pr_url.endswith("/pull/123"):
            print("   [SUCCESS] PRAnalysis retrieval successful")
        else:
            print("   [ERROR] PRAnalysis retrieval failed")
            return False
        
        # Test 5: Test backward compatibility
        print("5. Testing backward compatibility...")
        
        # Check if legacy tables still exist
        with sqlite3.connect(test_db_path) as conn:
            cursor = conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='threat_documents'
            """)
            if cursor.fetchone():
                print("   [SUCCESS] Legacy threat_documents table exists")
            else:
                print("   [ERROR] Legacy threat_documents table missing")
                return False
        
        # Test 6: Test migration rollback (optional)
        print("6. Testing migration rollback...")
        current_version = manager.get_current_version()
        if current_version > 1:
            rollback_result = manager.rollback_migration(current_version - 1)
            if rollback_result['success']:
                print("   [SUCCESS] Migration rollback successful")
                
                # Re-apply to restore state
                apply_result = manager.apply_migrations()
                if apply_result['success']:
                    print("   [SUCCESS] Migration re-application successful")
                else:
                    print("   [ERROR] Migration re-application failed")
                    return False
            else:
                print(f"   [ERROR] Migration rollback failed: {rollback_result['errors']}")
                return False
        else:
            print("   [WARNING] Skipping rollback test (only one migration)")
        
        print("\n[SUCCESS] All migration tests passed!")
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Migration test failed with error: {e}")
        return False
        
    finally:
        # Clean up temporary database
        try:
            os.unlink(test_db_path)
        except:
            pass

def test_migration_script():
    """Test the standalone migration script"""
    print("\nTesting Standalone Migration Script")
    print("=" * 40)
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
        test_db_path = tmp_db.name
    
    try:
        # Set environment variable for test database
        original_db_path = os.environ.get('DATABASE_PATH')
        os.environ['DATABASE_PATH'] = test_db_path
        
        # Test script execution
        import subprocess
        
        # Test status command
        result = subprocess.run([
            sys.executable, 'migrate_database.py', '--status'
        ], capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode == 0:
            print("   [SUCCESS] Migration script --status works")
        else:
            print(f"   [ERROR] Migration script --status failed: {result.stderr}")
            return False
        
        # Test validation command
        result = subprocess.run([
            sys.executable, 'migrate_database.py', '--validate'
        ], capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode == 0:
            print("   [SUCCESS] Migration script --validate works")
        else:
            print(f"   [ERROR] Migration script --validate failed: {result.stderr}")
            return False
        
        print("\n[SUCCESS] Migration script tests passed!")
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Migration script test failed: {e}")
        return False
        
    finally:
        # Restore original environment
        if original_db_path:
            os.environ['DATABASE_PATH'] = original_db_path
        elif 'DATABASE_PATH' in os.environ:
            del os.environ['DATABASE_PATH']
        
        # Clean up
        try:
            os.unlink(test_db_path)
        except:
            pass

def main():
    """Run all tests"""
    print("Database Migration Test Suite")
    print("=" * 50)
    
    success = True
    
    # Test migration system
    if not test_migration_system():
        success = False
    
    # Test migration script
    if not test_migration_script():
        success = False
    
    if success:
        print("\n[SUCCESS] All tests passed! Migration system is working correctly.")
        return 0
    else:
        print("\n[ERROR] Some tests failed. Please check the migration system.")
        return 1

if __name__ == "__main__":
    sys.exit(main())