#!/usr/bin/env python3
"""
Update script to replace LLM calls with task-based routing
"""

import re
import os

def update_threat_analysis_provider():
    """Update threat_analysis_provider.py to use task routing"""
    file_path = "api/threat_analysis_provider.py"
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Define the replacements for different methods
    replacements = [
        # STRIDE analysis - Creative task
        {
            'old': '''response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt(),
                temperature=0.4,
                max_tokens=4000
            )''',
            'new': '''response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.THREAT_BRAINSTORMING,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )''',
            'context': '_generate_stride_content'
        },
        # OWASP analysis - Analytical task
        {
            'old': '''response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt(),
                temperature=0.3,
                max_tokens=5000
            )''',
            'new': '''response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.COMPLIANCE_ANALYSIS,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )''',
            'context': '_generate_owasp_content'
        },
        # Component analysis - Standard task
        {
            'old': '''response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt(),
                temperature=0.3,
                max_tokens=3000
            )''',
            'new': '''response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.COMPONENT_ANALYSIS,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )''',
            'context': '_generate_component_content'
        },
        # Flow analysis - Creative task
        {
            'old': '''response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt(),
                temperature=0.4,
                max_tokens=4000
            )''',
            'new': '''response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.FLOW_THREAT_ANALYSIS,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )''',
            'context': '_generate_flow_content'
        },
        # System overview - Standard task
        {
            'old': '''response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt(),
                temperature=0.3,
                max_tokens=3000
            )''',
            'new': '''response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.SECURITY_OVERVIEW,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )''',
            'context': '_generate_system_overview_content'
        },
        # Mitigations - Analytical task
        {
            'old': '''response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt(),
                temperature=0.2,
                max_tokens=5000
            )''',
            'new': '''response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.MITIGATION_RECOMMENDATIONS,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )''',
            'context': '_generate_mitigations_content'
        }
    ]
    
    # Apply replacements
    for replacement in replacements:
        if replacement['old'] in content:
            content = content.replace(replacement['old'], replacement['new'])
            print(f"✅ Updated {replacement['context']} method")
        else:
            print(f"⚠️  Could not find exact match for {replacement['context']}")
    
    # Also need to update response.content references to response_content
    content = content.replace('response.content', 'response_content')
    
    # Write back
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"✅ Updated {file_path}")

def update_threat_docs():
    """Update threat_docs.py to use task routing"""
    file_path = "api/threat_docs.py"
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Add import
    if 'from .task_llm_router import get_task_router, TaskType' not in content:
        content = content.replace(
            'from .llm_client import LLMManager',
            'from .task_llm_router import get_task_router, TaskType'
        )
    
    # Replace LLMManager with task_router
    content = content.replace(
        'self.llm_manager = LLMManager()',
        'self.task_router = get_task_router()'
    )
    
    # Update specific method calls with their task types
    replacements = [
        # System overview
        ('temperature=0.3  # Lower temperature for more consistent output', 'TaskType.SECURITY_OVERVIEW'),
        # Component profile  
        ('temperature=0.3', 'TaskType.COMPONENT_ANALYSIS'),
        # Flow threat model - creative
        ('temperature=0.4,  # Slightly higher temperature for more creative threat analysis', 'TaskType.FLOW_THREAT_ANALYSIS'),
        # Mitigations - analytical
        ('temperature=0.2,  # Lower temperature for consistent recommendations', 'TaskType.MITIGATION_RECOMMENDATIONS'),
    ]
    
    # Write back
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"✅ Updated {file_path}")

if __name__ == "__main__":
    print("🔄 Updating files to use task-based routing...")
    
    try:
        update_threat_analysis_provider()
        print("\n✅ All files updated successfully!")
        print("\n📋 Next steps:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Test the system: python -m uvicorn api.main:app --reload")
        print("3. The system now uses task-effectiveness routing!")
        
    except Exception as e:
        print(f"❌ Error updating files: {e}")