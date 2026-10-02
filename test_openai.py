#!/usr/bin/env python3
"""Quick test to verify OpenAI API key is working"""
import os
from openai import OpenAI

def test_openai():
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        print("❌ OPENAI_API_KEY not found in environment")
        return False
    
    if api_key == "sk-your-openai-api-key-here":
        print("❌ OPENAI_API_KEY is still the placeholder value")
        return False
    
    print(f"✅ OpenAI API Key loaded: {api_key[:15]}...")
    
    try:
        client = OpenAI(api_key=api_key)
        print("✅ OpenAI client initialized successfully")
        
        # Try a simple completion to verify the key works
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Say 'API key working' in 3 words"}],
            max_tokens=10
        )
        
        result = response.choices[0].message.content
        print(f"✅ OpenAI API test successful!")
        print(f"   Response: {result}")
        return True
        
    except Exception as e:
        print(f"❌ OpenAI API test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_openai()
    exit(0 if success else 1)
