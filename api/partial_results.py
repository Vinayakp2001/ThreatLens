"""
Partial results storage and recovery system for analysis pipeline
"""
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

from .config import settings
from .models import RepoContext, SecurityModel, ThreatDoc, Component, Flow

logger = logging.getLogger(__name__)


class AnalysisStage(Enum):
    """Stages of the analysis pipeline"""
    REPOSITORY_INGESTION = "repository_ingestion"
    STRUCTURE_ANALYSIS = "structure_analysis"
    SECURITY_MODEL_BUILDING = "security_model_building"
    DOCUMENT_GENERATION = "document_generation"
    RAG_INDEXING = "rag_indexing"
    COMPLETED = "completed"


class AnalysisStatus(Enum):
    """Status of analysis stages"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    RECOVERED = "recovered"


@dataclass
class StageResult:
    """Result of an analysis stage"""
    stage: AnalysisStage
    status: AnalysisStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    retry_count: int = 0
    data: Optional[Dict[str, Any]] = None


@dataclass
class AnalysisProgress:
    """Overall analysis progress tracking"""
    analysis_id: str
    repo_id: str
    repo_url: Optional[str]
    local_path: Optional[str]
    current_stage: AnalysisStage
    overall_status: AnalysisStatus
    created_at: datetime
    updated_at: datetime
    stages: Dict[AnalysisStage, StageResult]
    partial_results: Dict[str, Any]
    error_recovery_attempts: int = 0


class PartialResultsManager:
    """Manages partial results and recovery for analysis pipeline"""
    
    def __init__(self):
        self.storage_path = Path(settings.storage_base_path) / "partial_results"
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.max_recovery_attempts = 3
        self.recovery_delay_seconds = 30
    
    def create_analysis_progress(
        self, 
        analysis_id: str, 
        repo_id: str, 
        repo_url: Optional[str] = None,
        local_path: Optional[str] = None
    ) -> AnalysisProgress:
        """Create new analysis progress tracking"""
        
        progress = AnalysisProgress(
            analysis_id=analysis_id,
            repo_id=repo_id,
            repo_url=repo_url,
            local_path=local_path,
            current_stage=AnalysisStage.REPOSITORY_INGESTION,
            overall_status=AnalysisStatus.NOT_STARTED,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            stages={},
            partial_results={}
        )
        
        # Initialize all stages
        for stage in AnalysisStage:
            progress.stages[stage] = StageResult(
                stage=stage,
                status=AnalysisStatus.NOT_STARTED,
                start_time=datetime.now()
            )
        
        self._save_progress(progress)
        logger.info(f"Created analysis progress tracking: {analysis_id}")
        
        return progress
    
    def start_stage(self, analysis_id: str, stage: AnalysisStage) -> AnalysisProgress:
        """Mark a stage as started"""
        progress = self.load_progress(analysis_id)
        if not progress:
            raise ValueError(f"Analysis progress not found: {analysis_id}")
        
        progress.current_stage = stage
        progress.overall_status = AnalysisStatus.IN_PROGRESS
        progress.updated_at = datetime.now()
        
        stage_result = progress.stages[stage]
        stage_result.status = AnalysisStatus.IN_PROGRESS
        stage_result.start_time = datetime.now()
        stage_result.retry_count += 1
        
        self._save_progress(progress)
        logger.info(f"Started stage {stage.value} for analysis {analysis_id}")
        
        return progress
    
    def complete_stage(
        self, 
        analysis_id: str, 
        stage: AnalysisStage, 
        result_data: Optional[Dict[str, Any]] = None
    ) -> AnalysisProgress:
        """Mark a stage as completed with optional result data"""
        progress = self.load_progress(analysis_id)
        if not progress:
            raise ValueError(f"Analysis progress not found: {analysis_id}")
        
        progress.updated_at = datetime.now()
        
        stage_result = progress.stages[stage]
        stage_result.status = AnalysisStatus.COMPLETED
        stage_result.end_time = datetime.now()
        stage_result.data = result_data
        
        # Store partial results
        if result_data:
            progress.partial_results[stage.value] = result_data
        
        # Check if all stages are complete
        if all(s.status == AnalysisStatus.COMPLETED for s in progress.stages.values()):
            progress.overall_status = AnalysisStatus.COMPLETED
            progress.current_stage = AnalysisStage.COMPLETED
        
        self._save_progress(progress)
        logger.info(f"Completed stage {stage.value} for analysis {analysis_id}")
        
        return progress
    
    def fail_stage(
        self, 
        analysis_id: str, 
        stage: AnalysisStage, 
        error_message: str,
        error_type: Optional[str] = None
    ) -> AnalysisProgress:
        """Mark a stage as failed"""
        progress = self.load_progress(analysis_id)
        if not progress:
            raise ValueError(f"Analysis progress not found: {analysis_id}")
        
        progress.updated_at = datetime.now()
        progress.overall_status = AnalysisStatus.FAILED
        
        stage_result = progress.stages[stage]
        stage_result.status = AnalysisStatus.FAILED
        stage_result.end_time = datetime.now()
        stage_result.error_message = error_message
        stage_result.error_type = error_type
        
        self._save_progress(progress)
        logger.error(f"Failed stage {stage.value} for analysis {analysis_id}: {error_message}")
        
        return progress
    
    def can_recover_stage(self, analysis_id: str, stage: AnalysisStage) -> bool:
        """Check if a stage can be recovered"""
        progress = self.load_progress(analysis_id)
        if not progress:
            return False
        
        stage_result = progress.stages.get(stage)
        if not stage_result:
            return False
        
        # Check retry limits
        if stage_result.retry_count >= self.max_recovery_attempts:
            return False
        
        # Check overall recovery attempts
        if progress.error_recovery_attempts >= self.max_recovery_attempts:
            return False
        
        return stage_result.status == AnalysisStatus.FAILED
    
    def recover_stage(self, analysis_id: str, stage: AnalysisStage) -> Optional[AnalysisProgress]:
        """Attempt to recover a failed stage"""
        if not self.can_recover_stage(analysis_id, stage):
            return None
        
        progress = self.load_progress(analysis_id)
        progress.error_recovery_attempts += 1
        progress.updated_at = datetime.now()
        
        # Reset stage status for retry
        stage_result = progress.stages[stage]
        stage_result.status = AnalysisStatus.NOT_STARTED
        stage_result.error_message = None
        stage_result.error_type = None
        stage_result.end_time = None
        
        self._save_progress(progress)
        logger.info(f"Recovering stage {stage.value} for analysis {analysis_id} (attempt {progress.error_recovery_attempts})")
        
        return progress
    
    def get_partial_results(self, analysis_id: str, stage: AnalysisStage) -> Optional[Dict[str, Any]]:
        """Get partial results for a specific stage"""
        progress = self.load_progress(analysis_id)
        if not progress:
            return None
        
        return progress.partial_results.get(stage.value)
    
    def get_completed_stages(self, analysis_id: str) -> List[AnalysisStage]:
        """Get list of completed stages"""
        progress = self.load_progress(analysis_id)
        if not progress:
            return []
        
        return [
            stage for stage, result in progress.stages.items()
            if result.status == AnalysisStatus.COMPLETED
        ]
    
    def can_skip_to_stage(self, analysis_id: str, target_stage: AnalysisStage) -> bool:
        """Check if we can skip to a specific stage based on completed stages"""
        completed_stages = self.get_completed_stages(analysis_id)
        
        # Define stage dependencies
        stage_order = [
            AnalysisStage.REPOSITORY_INGESTION,
            AnalysisStage.STRUCTURE_ANALYSIS,
            AnalysisStage.SECURITY_MODEL_BUILDING,
            AnalysisStage.DOCUMENT_GENERATION,
            AnalysisStage.RAG_INDEXING,
            AnalysisStage.COMPLETED
        ]
        
        target_index = stage_order.index(target_stage)
        
        # Check if all prerequisite stages are completed
        for i in range(target_index):
            if stage_order[i] not in completed_stages:
                return False
        
        return True
    
    def load_progress(self, analysis_id: str) -> Optional[AnalysisProgress]:
        """Load analysis progress from storage"""
        progress_file = self.storage_path / f"{analysis_id}.json"
        
        if not progress_file.exists():
            return None
        
        try:
            with open(progress_file, 'r') as f:
                data = json.load(f)
            
            # Convert string keys back to enums
            stages = {}
            for stage_name, stage_data in data['stages'].items():
                stage = AnalysisStage(stage_name)
                stages[stage] = StageResult(
                    stage=stage,
                    status=AnalysisStatus(stage_data['status']),
                    start_time=datetime.fromisoformat(stage_data['start_time']),
                    end_time=datetime.fromisoformat(stage_data['end_time']) if stage_data.get('end_time') else None,
                    error_message=stage_data.get('error_message'),
                    error_type=stage_data.get('error_type'),
                    retry_count=stage_data.get('retry_count', 0),
                    data=stage_data.get('data')
                )
            
            progress = AnalysisProgress(
                analysis_id=data['analysis_id'],
                repo_id=data['repo_id'],
                repo_url=data.get('repo_url'),
                local_path=data.get('local_path'),
                current_stage=AnalysisStage(data['current_stage']),
                overall_status=AnalysisStatus(data['overall_status']),
                created_at=datetime.fromisoformat(data['created_at']),
                updated_at=datetime.fromisoformat(data['updated_at']),
                stages=stages,
                partial_results=data.get('partial_results', {}),
                error_recovery_attempts=data.get('error_recovery_attempts', 0)
            )
            
            return progress
            
        except Exception as e:
            logger.error(f"Failed to load progress for {analysis_id}: {e}")
            return None
    
    def _save_progress(self, progress: AnalysisProgress):
        """Save analysis progress to storage"""
        progress_file = self.storage_path / f"{progress.analysis_id}.json"
        
        try:
            # Convert to serializable format
            data = {
                'analysis_id': progress.analysis_id,
                'repo_id': progress.repo_id,
                'repo_url': progress.repo_url,
                'local_path': progress.local_path,
                'current_stage': progress.current_stage.value,
                'overall_status': progress.overall_status.value,
                'created_at': progress.created_at.isoformat(),
                'updated_at': progress.updated_at.isoformat(),
                'stages': {},
                'partial_results': progress.partial_results,
                'error_recovery_attempts': progress.error_recovery_attempts
            }
            
            # Convert stages
            for stage, result in progress.stages.items():
                data['stages'][stage.value] = {
                    'status': result.status.value,
                    'start_time': result.start_time.isoformat(),
                    'end_time': result.end_time.isoformat() if result.end_time else None,
                    'error_message': result.error_message,
                    'error_type': result.error_type,
                    'retry_count': result.retry_count,
                    'data': result.data
                }
            
            with open(progress_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save progress for {progress.analysis_id}: {e}")
    
    def cleanup_old_progress(self, days_old: int = 7):
        """Clean up old progress files"""
        cutoff_time = time.time() - (days_old * 24 * 60 * 60)
        
        try:
            for progress_file in self.storage_path.glob("*.json"):
                if progress_file.stat().st_mtime < cutoff_time:
                    progress_file.unlink()
                    logger.info(f"Cleaned up old progress file: {progress_file.name}")
        except Exception as e:
            logger.error(f"Failed to cleanup old progress files: {e}")
    
    def get_all_progress(self) -> List[AnalysisProgress]:
        """Get all analysis progress records"""
        progress_list = []
        
        try:
            for progress_file in self.storage_path.glob("*.json"):
                analysis_id = progress_file.stem
                progress = self.load_progress(analysis_id)
                if progress:
                    progress_list.append(progress)
        except Exception as e:
            logger.error(f"Failed to load all progress records: {e}")
        
        return progress_list
    
    def get_failed_analyses(self) -> List[AnalysisProgress]:
        """Get all failed analyses that can potentially be recovered"""
        all_progress = self.get_all_progress()
        
        return [
            progress for progress in all_progress
            if progress.overall_status == AnalysisStatus.FAILED and
            progress.error_recovery_attempts < self.max_recovery_attempts
        ]