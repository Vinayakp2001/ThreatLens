"""
Wiki storage management system for security wiki persistence and retrieval
"""
import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from .models import SecurityWiki, WikiSection, SecurityFinding
from .storage_manager import StorageManager, StorageType
from .database import DatabaseManager
from .config import settings


logger = logging.getLogger(__name__)


class WikiStorage:
    """Storage management for security wikis extending existing storage capabilities"""
    
    def __init__(self, storage_manager: Optional[StorageManager] = None, db_manager: Optional[DatabaseManager] = None):
        self.storage_manager = storage_manager or StorageManager()
        self.db_manager = db_manager or DatabaseManager()
        
        # Create wiki-specific storage directory
        self.wiki_storage_path = self.storage_manager.get_storage_path(StorageType.DOCUMENTS) / "wikis"
        self.wiki_storage_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize wiki search index directory
        self.wiki_index_path = self.storage_manager.get_storage_path(StorageType.EMBEDDINGS) / "wiki_index"
        self.wiki_index_path.mkdir(parents=True, exist_ok=True)
    
    def save_wiki(self, wiki: SecurityWiki) -> bool:
        """Save security wiki with both database and file storage"""
        try:
            # Save to database for structured queries
            db_success = self._save_wiki_to_database(wiki)
            if not db_success:
                logger.error(f"Failed to save wiki {wiki.id} to database")
                return False
            
            # Save to file system for backup and direct access
            file_success = self._save_wiki_to_file(wiki)
            if not file_success:
                logger.warning(f"Failed to save wiki {wiki.id} to file system")
                # Don't fail the operation if file save fails, database is primary
            
            # Update search index
            index_success = self._update_wiki_search_index(wiki)
            if not index_success:
                logger.warning(f"Failed to update search index for wiki {wiki.id}")
            
            logger.info(f"Successfully saved wiki {wiki.id}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving wiki {wiki.id}: {e}")
            return False
    
    def load_wiki(self, wiki_id: str) -> Optional[SecurityWiki]:
        """Load security wiki by ID"""
        try:
            # Try database first
            wiki = self._load_wiki_from_database(wiki_id)
            if wiki:
                return wiki
            
            # Fallback to file system
            wiki = self._load_wiki_from_file(wiki_id)
            if wiki:
                logger.info(f"Loaded wiki {wiki_id} from file system fallback")
                return wiki
            
            logger.warning(f"Wiki {wiki_id} not found in database or file system")
            return None
            
        except Exception as e:
            logger.error(f"Error loading wiki {wiki_id}: {e}")
            return None
    
    def get_wikis_by_repo(self, repo_id: str) -> List[SecurityWiki]:
        """Get all wikis for a repository"""
        try:
            return self._get_wikis_by_repo_from_database(repo_id)
        except Exception as e:
            logger.error(f"Error getting wikis for repo {repo_id}: {e}")
            return []
    
    def get_wiki_section(self, wiki_id: str, section_id: str) -> Optional[WikiSection]:
        """Get specific wiki section"""
        try:
            wiki = self.load_wiki(wiki_id)
            if not wiki:
                return None
            
            return wiki.sections.get(section_id)
            
        except Exception as e:
            logger.error(f"Error getting wiki section {section_id} from wiki {wiki_id}: {e}")
            return None
    
    def update_wiki_section(self, wiki_id: str, section_id: str, section: WikiSection) -> bool:
        """Update specific wiki section"""
        try:
            wiki = self.load_wiki(wiki_id)
            if not wiki:
                logger.error(f"Wiki {wiki_id} not found")
                return False
            
            # Update section
            wiki.sections[section_id] = section
            wiki.updated_at = datetime.now()
            
            # Save updated wiki
            return self.save_wiki(wiki)
            
        except Exception as e:
            logger.error(f"Error updating wiki section {section_id}: {e}")
            return False
    
    def search_wiki_content(self, repo_id: str, query: str, section_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search wiki content using existing embedding capabilities"""
        try:
            # Get all wikis for repository
            wikis = self.get_wikis_by_repo(repo_id)
            if not wikis:
                return []
            
            search_results = []
            
            for wiki in wikis:
                for section_id, section in wiki.sections.items():
                    # Filter by section type if specified
                    if section_type and section_id != section_type:
                        continue
                    
                    # Simple text search (can be enhanced with embeddings later)
                    if query.lower() in section.content.lower() or query.lower() in section.title.lower():
                        # Calculate relevance score based on query matches
                        content_matches = section.content.lower().count(query.lower())
                        title_matches = section.title.lower().count(query.lower()) * 2  # Weight title matches higher
                        relevance_score = (content_matches + title_matches) / len(section.content)
                        
                        # Extract content snippet around first match
                        content_lower = section.content.lower()
                        query_lower = query.lower()
                        match_index = content_lower.find(query_lower)
                        
                        if match_index != -1:
                            start = max(0, match_index - 100)
                            end = min(len(section.content), match_index + len(query) + 100)
                            snippet = section.content[start:end]
                            if start > 0:
                                snippet = "..." + snippet
                            if end < len(section.content):
                                snippet = snippet + "..."
                        else:
                            snippet = section.content[:200] + "..." if len(section.content) > 200 else section.content
                        
                        search_results.append({
                            "wiki_id": wiki.id,
                            "section_id": section_id,
                            "section_title": section.title,
                            "content_snippet": snippet,
                            "relevance_score": relevance_score,
                            "code_references": [ref.dict() for ref in section.code_references],
                            "security_findings": [finding.dict() for finding in section.security_findings]
                        })
            
            # Sort by relevance score
            search_results.sort(key=lambda x: x["relevance_score"], reverse=True)
            return search_results
            
        except Exception as e:
            logger.error(f"Error searching wiki content: {e}")
            return []
    
    def get_wiki_statistics(self, repo_id: str) -> Dict[str, Any]:
        """Get comprehensive statistics for repository wikis"""
        try:
            wikis = self.get_wikis_by_repo(repo_id)
            
            total_sections = 0
            total_findings = 0
            total_code_refs = 0
            section_types = set()
            
            for wiki in wikis:
                total_sections += len(wiki.sections)
                
                for section in wiki.sections.values():
                    section_types.add(section.id)
                    total_findings += len(section.security_findings)
                    total_code_refs += len(section.code_references)
            
            return {
                "repo_id": repo_id,
                "total_wikis": len(wikis),
                "total_sections": total_sections,
                "total_security_findings": total_findings,
                "total_code_references": total_code_refs,
                "section_types": list(section_types),
                "last_updated": max([wiki.updated_at or wiki.created_at for wiki in wikis]) if wikis else None
            }
            
        except Exception as e:
            logger.error(f"Error getting wiki statistics for repo {repo_id}: {e}")
            return {}
    
    def cleanup_old_wikis(self, repo_id: str, keep_latest: int = 5) -> bool:
        """Clean up old wiki versions for a repository"""
        try:
            wikis = self.get_wikis_by_repo(repo_id)
            
            if len(wikis) <= keep_latest:
                return True
            
            # Sort by creation date, keep the latest ones
            wikis.sort(key=lambda w: w.created_at, reverse=True)
            wikis_to_delete = wikis[keep_latest:]
            
            for wiki in wikis_to_delete:
                # Delete from database
                self._delete_wiki_from_database(wiki.id)
                
                # Delete from file system
                self._delete_wiki_from_file(wiki.id)
                
                # Remove from search index
                self._remove_from_search_index(wiki.id)
                
                logger.info(f"Cleaned up old wiki {wiki.id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error cleaning up old wikis for repo {repo_id}: {e}")
            return False
    
    def _save_wiki_to_database(self, wiki: SecurityWiki) -> bool:
        """Save wiki to database"""
        try:
            # Convert wiki to database format
            wiki_data = {
                "id": wiki.id,
                "repo_id": wiki.repo_id,
                "title": wiki.title,
                "sections": json.dumps({k: v.dict() for k, v in wiki.sections.items()}),
                "cross_references": json.dumps(wiki.cross_references),
                "search_index": json.dumps(wiki.search_index),
                "metadata": json.dumps(wiki.metadata),
                "created_at": wiki.created_at,
                "updated_at": wiki.updated_at or datetime.now()
            }
            
            # Use existing database manager with new table
            return self.db_manager.execute_query(
                """
                INSERT OR REPLACE INTO security_wikis 
                (id, repo_id, title, sections, cross_references, search_index, metadata, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(wiki_data.values())
            )
            
        except Exception as e:
            logger.error(f"Error saving wiki to database: {e}")
            return False
    
    def _save_wiki_to_file(self, wiki: SecurityWiki) -> bool:
        """Save wiki to file system"""
        try:
            repo_dir = self.wiki_storage_path / wiki.repo_id
            repo_dir.mkdir(exist_ok=True)
            
            # Save as JSON for structured access
            json_file = repo_dir / f"wiki_{wiki.id}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(wiki.dict(), f, indent=2, default=str)
            
            # Save as markdown for human readability
            md_file = repo_dir / f"wiki_{wiki.id}.md"
            with open(md_file, 'w', encoding='utf-8') as f:
                f.write(self._create_wiki_markdown(wiki))
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving wiki to file: {e}")
            return False
    
    def _create_wiki_markdown(self, wiki: SecurityWiki) -> str:
        """Create markdown representation of wiki"""
        content = f"# {wiki.title}\n\n"
        content += f"**Repository:** {wiki.repo_id}\n"
        content += f"**Created:** {wiki.created_at}\n"
        if wiki.updated_at:
            content += f"**Updated:** {wiki.updated_at}\n"
        content += "\n---\n\n"
        
        # Table of contents
        content += "## Table of Contents\n\n"
        for section_id, section in wiki.sections.items():
            content += f"- [{section.title}](#{section_id.replace('_', '-')})\n"
        content += "\n"
        
        # Sections
        for section_id, section in wiki.sections.items():
            content += f"## {section.title} {{#{section_id}}}\n\n"
            content += section.content + "\n\n"
            
            # Add security findings if present
            if section.security_findings:
                content += "### Security Findings\n\n"
                for finding in section.security_findings:
                    content += f"- **{finding.type.upper()}** ({finding.severity}): {finding.description}\n"
                content += "\n"
            
            # Add code references if present
            if section.code_references:
                content += "### Code References\n\n"
                for ref in section.code_references:
                    content += f"- `{ref.file_path}`"
                    if ref.function_name:
                        content += f" (Function: {ref.function_name})"
                    if ref.line_start:
                        content += f" (Lines: {ref.line_start}"
                        if ref.line_end and ref.line_end != ref.line_start:
                            content += f"-{ref.line_end}"
                        content += ")"
                    content += "\n"
                content += "\n"
            
            # Add cross-references if present
            if section.cross_references:
                content += "### Related Sections\n\n"
                for ref in section.cross_references:
                    content += f"- [{ref}](#{ref.replace('_', '-')})\n"
                content += "\n"
            
            content += "---\n\n"
        
        return content  
  
    def _load_wiki_from_database(self, wiki_id: str) -> Optional[SecurityWiki]:
        """Load wiki from database"""
        try:
            result = self.db_manager.fetch_one(
                "SELECT * FROM security_wikis WHERE id = ?",
                (wiki_id,)
            )
            
            if not result:
                return None
            
            # Convert database result to SecurityWiki
            sections_data = json.loads(result["sections"])
            sections = {}
            
            for section_id, section_data in sections_data.items():
                # Convert security findings
                findings = []
                for finding_data in section_data.get("security_findings", []):
                    findings.append(SecurityFinding(**finding_data))
                
                # Convert code references
                code_refs = []
                for ref_data in section_data.get("code_references", []):
                    from .models import CodeReference
                    code_refs.append(CodeReference(**ref_data))
                
                # Create WikiSection
                section_data["security_findings"] = findings
                section_data["code_references"] = code_refs
                sections[section_id] = WikiSection(**section_data)
            
            return SecurityWiki(
                id=result["id"],
                repo_id=result["repo_id"],
                title=result["title"],
                sections=sections,
                cross_references=json.loads(result["cross_references"]),
                search_index=json.loads(result["search_index"]),
                metadata=json.loads(result["metadata"]),
                created_at=datetime.fromisoformat(result["created_at"]),
                updated_at=datetime.fromisoformat(result["updated_at"]) if result["updated_at"] else None
            )
            
        except Exception as e:
            logger.error(f"Error loading wiki from database: {e}")
            return None
    
    def _load_wiki_from_file(self, wiki_id: str) -> Optional[SecurityWiki]:
        """Load wiki from file system"""
        try:
            # Search for the wiki file across all repo directories
            for repo_dir in self.wiki_storage_path.iterdir():
                if repo_dir.is_dir():
                    json_file = repo_dir / f"wiki_{wiki_id}.json"
                    if json_file.exists():
                        with open(json_file, 'r', encoding='utf-8') as f:
                            wiki_data = json.load(f)
                        
                        # Convert to SecurityWiki object
                        return SecurityWiki(**wiki_data)
            
            return None
            
        except Exception as e:
            logger.error(f"Error loading wiki from file: {e}")
            return None
    
    def _get_wikis_by_repo_from_database(self, repo_id: str) -> List[SecurityWiki]:
        """Get all wikis for a repository from database"""
        try:
            results = self.db_manager.fetch_all(
                "SELECT * FROM security_wikis WHERE repo_id = ? ORDER BY created_at DESC",
                (repo_id,)
            )
            
            wikis = []
            for result in results:
                wiki = self._load_wiki_from_database(result["id"])
                if wiki:
                    wikis.append(wiki)
            
            return wikis
            
        except Exception as e:
            logger.error(f"Error getting wikis from database: {e}")
            return []
    
    def _update_wiki_search_index(self, wiki: SecurityWiki) -> bool:
        """Update search index for wiki using existing embedding capabilities"""
        try:
            # Create search index entries for each section
            search_entries = []
            
            for section_id, section in wiki.sections.items():
                # Create searchable content
                searchable_content = f"{section.title}\n{section.content}"
                
                # Add security findings to searchable content
                for finding in section.security_findings:
                    searchable_content += f"\n{finding.type}: {finding.description}"
                
                search_entries.append({
                    "id": f"{wiki.id}_{section_id}",
                    "wiki_id": wiki.id,
                    "section_id": section_id,
                    "content": searchable_content,
                    "metadata": {
                        "section_title": section.title,
                        "security_findings_count": len(section.security_findings),
                        "code_references_count": len(section.code_references)
                    }
                })
            
            # Save search index to file
            index_file = self.wiki_index_path / f"wiki_{wiki.id}_index.json"
            with open(index_file, 'w', encoding='utf-8') as f:
                json.dump(search_entries, f, indent=2)
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating wiki search index: {e}")
            return False
    
    def _delete_wiki_from_database(self, wiki_id: str) -> bool:
        """Delete wiki from database"""
        try:
            return self.db_manager.execute_query(
                "DELETE FROM security_wikis WHERE id = ?",
                (wiki_id,)
            )
        except Exception as e:
            logger.error(f"Error deleting wiki from database: {e}")
            return False
    
    def _delete_wiki_from_file(self, wiki_id: str) -> bool:
        """Delete wiki files from file system"""
        try:
            # Search and delete wiki files across all repo directories
            for repo_dir in self.wiki_storage_path.iterdir():
                if repo_dir.is_dir():
                    json_file = repo_dir / f"wiki_{wiki_id}.json"
                    md_file = repo_dir / f"wiki_{wiki_id}.md"
                    
                    if json_file.exists():
                        json_file.unlink()
                    if md_file.exists():
                        md_file.unlink()
            
            return True
            
        except Exception as e:
            logger.error(f"Error deleting wiki files: {e}")
            return False
    
    def _remove_from_search_index(self, wiki_id: str) -> bool:
        """Remove wiki from search index"""
        try:
            index_file = self.wiki_index_path / f"wiki_{wiki_id}_index.json"
            if index_file.exists():
                index_file.unlink()
            return True
            
        except Exception as e:
            logger.error(f"Error removing wiki from search index: {e}")
            return False


# Global wiki storage instance
wiki_storage = WikiStorage()