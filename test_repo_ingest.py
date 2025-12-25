#!/usr/bin/env python3
"""
Simple test script to verify repository ingestion functionality
"""
import sys
import os
import tempfile
import shutil
from pathlib import Path
sys.path.append('.')

from api.repo_ingest import RepoIngestor
from api.config import settings

def create_test_repo():
    """Create a small test repository structure"""
    test_dir = Path(tempfile.mkdtemp(prefix="test_repo_"))
    
    # Create directory structure
    (test_dir / "src").mkdir()
    (test_dir / "src" / "controllers").mkdir()
    (test_dir / "src" / "models").mkdir()
    (test_dir / "src" / "services").mkdir()
    (test_dir / "tests").mkdir()
    (test_dir / "config").mkdir()
    
    # Create sample files
    files_to_create = {
        "src/controllers/user_controller.py": '''
from flask import Flask, request, jsonify
from src.services.user_service import UserService

app = Flask(__name__)

@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users"""
    users = UserService.get_all_users()
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
def create_user():
    """Create a new user"""
    data = request.get_json()
    user = UserService.create_user(data)
    return jsonify(user), 201
''',
        "src/models/user.py": '''
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class User(Base):
    """User model for database"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(128))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'
''',
        "src/services/user_service.py": '''
from src.models.user import User
from werkzeug.security import generate_password_hash

class UserService:
    """Service class for user operations"""
    
    @staticmethod
    def get_all_users():
        """Get all users from database"""
        return User.query.all()
    
    @staticmethod
    def create_user(user_data):
        """Create a new user"""
        password_hash = generate_password_hash(user_data['password'])
        user = User(
            username=user_data['username'],
            email=user_data['email'],
            password_hash=password_hash
        )
        return user
''',
        "config/settings.py": '''
import os

class Config:
    """Application configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret'
''',
        "tests/test_user_controller.py": '''
import unittest
from src.controllers.user_controller import app

class TestUserController(unittest.TestCase):
    """Test cases for user controller"""
    
    def setUp(self):
        self.app = app.test_client()
    
    def test_get_users(self):
        """Test getting users endpoint"""
        response = self.app.get('/api/users')
        self.assertEqual(response.status_code, 200)
''',
        "requirements.txt": '''
flask>=2.0.0
sqlalchemy>=1.4.0
werkzeug>=2.0.0
''',
        "README.md": '''
# Test Repository

This is a test Flask application for demonstrating repository analysis.

## Features
- User management API
- SQLAlchemy models
- Service layer architecture
'''
    }
    
    # Write files
    for file_path, content in files_to_create.items():
        full_path = test_dir / file_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content.strip())
    
    return test_dir

def test_repo_ingestion():
    """Test repository ingestion with a small test repository"""
    print("Creating test repository...")
    test_repo_path = create_test_repo()
    
    try:
        print(f"Test repository created at: {test_repo_path}")
        print("Testing repository ingestion...")
        
        ingestor = RepoIngestor()
        
        # Test loading test repository
        repo_context = ingestor.load_local_repository(str(test_repo_path))
        print(f"✓ Successfully loaded repository: {repo_context.repo_id}")
        print(f"  Local path: {repo_context.local_path}")
        print(f"  Status: {repo_context.analysis_status}")
        
        # Test structure analysis
        structure_analysis = ingestor.analyze_structure(repo_context)
        print(f"✓ Structure analysis completed")
        print(f"  Total files: {structure_analysis.total_files}")
        print(f"  Primary languages: {structure_analysis.primary_languages}")
        print(f"  Key directories: {structure_analysis.key_directories}")
        print(f"  Detected frameworks: {structure_analysis.detected_frameworks}")
        
        # Print component analysis summary
        if 'component_analysis' in repo_context.structure_summary:
            comp_analysis = repo_context.structure_summary['component_analysis']
            print(f"  Component breakdown: {comp_analysis['summary']['component_breakdown']}")
            print(f"  API endpoints found: {comp_analysis['summary']['api_endpoints_count']}")
            print(f"  Database models found: {comp_analysis['summary']['database_models_count']}")
            
            # Show some detected components
            if comp_analysis['components']['controllers']:
                print(f"  Sample controller: {comp_analysis['components']['controllers'][0]['file_path']}")
            if comp_analysis['components']['models']:
                print(f"  Sample model: {comp_analysis['components']['models'][0]['file_path']}")
            if comp_analysis['api_endpoints']:
                print(f"  Sample endpoint: {comp_analysis['api_endpoints'][0]['method']} {comp_analysis['api_endpoints'][0]['path']}")
        
        print("\n✓ All tests passed!")
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Clean up test repository
        try:
            shutil.rmtree(test_repo_path)
            print(f"✓ Cleaned up test repository")
        except Exception as e:
            print(f"Warning: Could not clean up test repository: {e}")

def test_size_limit():
    """Test that the size limit is working correctly"""
    print("\nTesting size limit with current directory...")
    
    ingestor = RepoIngestor()
    
    try:
        # This should fail due to size limit
        repo_context = ingestor.load_local_repository(".")
        print("✗ Size limit test failed - should have been rejected")
        return False
    except Exception as e:
        if "exceeds limit" in str(e):
            print(f"✓ Size limit working correctly: {e}")
            return True
        else:
            print(f"✗ Unexpected error: {e}")
            return False

if __name__ == "__main__":
    success1 = test_repo_ingestion()
    success2 = test_size_limit()
    
    if success1 and success2:
        print("\n🎉 All tests passed! Repository ingestion is working correctly.")
    else:
        print("\n❌ Some tests failed.")
    
    sys.exit(0 if (success1 and success2) else 1)