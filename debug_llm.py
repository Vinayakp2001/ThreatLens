#!/usr/bin/env python3
"""
Debug script to test LLM connection step by step
"""
import os
import asyncio
import sys
from dotenv import load_dotenv

# Load environment
load_dotenv()

async def test_llm_step_by_step():
    """Test LLM connection with detailed debugging"""
    
    print("🔍 LLM Debug Test")
    print("=" * 50)
    
    # Step 1: Check environment variables
    print("\n1️⃣ Environment Variables:")
    google_api_key = os.getenv('GOOGLE_API_KEY')
    google_model = os.getenv('GOOGLE_MODEL')
    llm_provider = os.getenv('LLM_PROVIDER')
    
    print(f"   LLM_PROVIDER: {llm_provider}")
    print(f"   GOOGLE_MODEL: {google_model}")
    print(f"   GOOGLE_API_KEY: {google_api_key[:20] if google_api_key else 'None'}...")
    
    # Step 2: Test direct Google API (skip if quota exceeded)
    print("\n2️⃣ Direct Google API Test:")
    try:
        import google.generativeai as genai
        
        genai.configure(api_key=google_api_key)
        model = genai.GenerativeModel(google_model)
        
        response = model.generate_content("Test message. Reply with just 'OK'.")
        print(f"   ✅ Direct API works: {response.text}")
        
    except Exception as e:
        if "429" in str(e) or "quota" in str(e).lower():
            print(f"   ⚠️ Direct API quota exceeded (expected): {str(e)[:100]}...")
            print(f"   ℹ️ This is normal - we've been testing a lot!")
        else:
            print(f"   ❌ Direct API failed: {e}")
            return False
    
    # Step 3: Test backend LLM client
    print("\n3️⃣ Backend LLM Client Test:")
    try:
        # Import the backend LLM client
        sys.path.append('.')
        from api.llm_client import LLMManager
        from api.config import settings
        
        print(f"   Settings provider: {settings.llm_provider}")
        print(f"   Settings model: {settings.google_model}")
        
        llm_manager = LLMManager()
        print(f"   LLM Manager provider: {llm_manager.provider}")
        print(f"   LLM Manager model: {llm_manager.model}")
        
        # Test completion
        response = await llm_manager.generate_completion(
            "Test connection",
            max_tokens=10,
            temperature=0.1
        )
        
        print(f"   ✅ Backend LLM works: {response.content}")
        
    except Exception as e:
        print(f"   ❌ Backend LLM failed: {e}")
        print(f"   Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n🎉 All tests passed!")
    return True

if __name__ == "__main__":
    asyncio.run(test_llm_step_by_step())