"""
Resource Manager for CPU/GPU hybrid processing optimization.
Intelligently allocates computational resources based on system capabilities.
"""

import logging
import psutil
import torch
from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ProcessingMode(Enum):
    CPU_ONLY = "cpu_only"
    GPU_PREFERRED = "gpu_preferred"
    HYBRID = "hybrid"


@dataclass
class SystemCapabilities:
    """System hardware capabilities assessment"""
    cpu_cores: int
    total_ram_gb: float
    available_ram_gb: float
    has_gpu: bool
    gpu_memory_gb: Optional[float]
    gpu_name: Optional[str]
    storage_type: str  # SSD or HDD


@dataclass
class ResourceAllocation:
    """Resource allocation strategy for different operations"""
    embedding_batch_size: int
    vector_search_device: str  # 'cpu' or 'cuda'
    max_concurrent_operations: int
    use_gpu_for_embeddings: bool
    faiss_index_type: str  # 'cpu' or 'gpu'


class ResourceManager:
    """
    Smart resource allocation manager for CPU/GPU hybrid processing.
    
    Automatically detects system capabilities and optimizes resource usage
    for different operations in the threat modeling pipeline.
    """
    
    def __init__(self):
        self.capabilities = self._assess_system_capabilities()
        self.processing_mode = self._determine_processing_mode()
        self.allocation = self._create_resource_allocation()
        
        logger.info(f"ResourceManager initialized with mode: {self.processing_mode.value}")
        logger.info(f"System capabilities: {self.capabilities}")
    
    def _assess_system_capabilities(self) -> SystemCapabilities:
        """Assess current system hardware capabilities"""
        # CPU information
        cpu_cores = psutil.cpu_count(logical=True)
        
        # Memory information
        memory = psutil.virtual_memory()
        total_ram_gb = memory.total / (1024**3)
        available_ram_gb = memory.available / (1024**3)
        
        # GPU detection
        has_gpu = False
        gpu_memory_gb = None
        gpu_name = None
        
        try:
            if torch.cuda.is_available():
                has_gpu = True
                gpu_properties = torch.cuda.get_device_properties(0)
                gpu_memory_gb = gpu_properties.total_memory / (1024**3)
                gpu_name = gpu_properties.name
                logger.info(f"GPU detected: {gpu_name} with {gpu_memory_gb:.1f}GB VRAM")
            else:
                logger.info("No CUDA-capable GPU detected")
        except Exception as e:
            logger.warning(f"GPU detection failed: {e}")
        
        # Storage type detection (simplified)
        storage_type = "SSD"  # Assume SSD for modern systems
        
        return SystemCapabilities(
            cpu_cores=cpu_cores,
            total_ram_gb=total_ram_gb,
            available_ram_gb=available_ram_gb,
            has_gpu=has_gpu,
            gpu_memory_gb=gpu_memory_gb,
            gpu_name=gpu_name,
            storage_type=storage_type
        )
    
    def _determine_processing_mode(self) -> ProcessingMode:
        """Determine optimal processing mode based on system capabilities"""
        if not self.capabilities.has_gpu:
            return ProcessingMode.CPU_ONLY
        
        # Check if GPU has sufficient memory (minimum 1.5GB for basic operations)
        if self.capabilities.gpu_memory_gb and self.capabilities.gpu_memory_gb < 1.5:
            logger.info("GPU has insufficient memory (<1.5GB), using CPU-only mode")
            return ProcessingMode.CPU_ONLY
        
        # Check if system has sufficient RAM for hybrid processing
        if self.capabilities.available_ram_gb < 4.0:
            logger.info("Insufficient system RAM (<4GB), using CPU-only mode")
            return ProcessingMode.CPU_ONLY
        
        # Use hybrid mode for systems with capable GPU and sufficient RAM
        return ProcessingMode.HYBRID
    
    def _create_resource_allocation(self) -> ResourceAllocation:
        """Create resource allocation strategy based on processing mode"""
        if self.processing_mode == ProcessingMode.CPU_ONLY:
            return ResourceAllocation(
                embedding_batch_size=16,  # Conservative for CPU
                vector_search_device='cpu',
                max_concurrent_operations=min(4, self.capabilities.cpu_cores),
                use_gpu_for_embeddings=False,
                faiss_index_type='cpu'
            )
        
        elif self.processing_mode == ProcessingMode.HYBRID:
            # Optimize batch size based on GPU memory
            gpu_batch_size = 32
            if self.capabilities.gpu_memory_gb and self.capabilities.gpu_memory_gb < 3.0:
                gpu_batch_size = 16  # Smaller batches for limited VRAM
            
            return ResourceAllocation(
                embedding_batch_size=gpu_batch_size,
                vector_search_device='cuda',
                max_concurrent_operations=min(6, self.capabilities.cpu_cores + 2),
                use_gpu_for_embeddings=True,
                faiss_index_type='gpu'
            )
        
        else:  # GPU_PREFERRED (future enhancement)
            return ResourceAllocation(
                embedding_batch_size=64,
                vector_search_device='cuda',
                max_concurrent_operations=8,
                use_gpu_for_embeddings=True,
                faiss_index_type='gpu'
            )
    
    def get_embedding_config(self) -> Dict[str, Any]:
        """Get configuration for embedding generation"""
        return {
            'batch_size': self.allocation.embedding_batch_size,
            'device': 'cuda' if self.allocation.use_gpu_for_embeddings else 'cpu',
            'max_length': 512,  # Standard for sentence transformers
        }
    
    def get_faiss_config(self) -> Dict[str, Any]:
        """Get configuration for FAISS vector operations"""
        return {
            'index_type': self.allocation.faiss_index_type,
            'use_gpu': self.allocation.faiss_index_type == 'gpu',
            'gpu_device': 0 if self.allocation.faiss_index_type == 'gpu' else None,
        }
    
    def get_concurrency_config(self) -> Dict[str, Any]:
        """Get configuration for concurrent operations"""
        return {
            'max_workers': self.allocation.max_concurrent_operations,
            'thread_pool_size': min(8, self.capabilities.cpu_cores * 2),
            'async_batch_size': self.allocation.embedding_batch_size,
        }
    
    def monitor_resource_usage(self) -> Dict[str, float]:
        """Monitor current resource usage"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        gpu_usage = 0.0
        gpu_memory_percent = 0.0
        
        if self.capabilities.has_gpu:
            try:
                # Get GPU utilization if available
                import pynvml
                pynvml.nvmlInit()
                handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                gpu_info = pynvml.nvmlDeviceGetUtilizationRates(handle)
                gpu_usage = gpu_info.gpu
                
                memory_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
                gpu_memory_percent = (memory_info.used / memory_info.total) * 100
            except ImportError:
                logger.debug("pynvml not available for GPU monitoring")
            except Exception as e:
                logger.debug(f"GPU monitoring error: {e}")
        
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'gpu_percent': gpu_usage,
            'gpu_memory_percent': gpu_memory_percent,
        }
    
    def should_use_gpu_for_operation(self, operation_type: str, data_size: int) -> bool:
        """
        Decide whether to use GPU for a specific operation based on current conditions.
        
        Args:
            operation_type: Type of operation ('embedding', 'search', 'inference')
            data_size: Size of data to process (number of items)
        
        Returns:
            True if GPU should be used, False otherwise
        """
        if self.processing_mode == ProcessingMode.CPU_ONLY:
            return False
        
        # Check current resource usage
        usage = self.monitor_resource_usage()
        
        # Don't use GPU if it's already heavily loaded
        if usage['gpu_percent'] > 80 or usage['gpu_memory_percent'] > 85:
            logger.debug(f"GPU usage too high ({usage['gpu_percent']}%, {usage['gpu_memory_percent']}%), using CPU")
            return False
        
        # Use GPU for larger operations that benefit from parallelization
        if operation_type == 'embedding' and data_size > 10:
            return self.allocation.use_gpu_for_embeddings
        elif operation_type == 'search' and data_size > 100:
            return self.allocation.faiss_index_type == 'gpu'
        
        return False
    
    def get_optimal_batch_size(self, operation_type: str, total_items: int) -> int:
        """Get optimal batch size for processing operations"""
        base_batch_size = self.allocation.embedding_batch_size
        
        # Adjust batch size based on available memory and operation type
        if operation_type == 'embedding':
            # Smaller batches for CPU to avoid memory pressure
            if not self.allocation.use_gpu_for_embeddings:
                return min(base_batch_size, 8)
            return base_batch_size
        
        elif operation_type == 'search':
            # Larger batches for search operations
            return min(base_batch_size * 2, 64)
        
        return base_batch_size


# Global resource manager instance
_resource_manager: Optional[ResourceManager] = None


def get_resource_manager() -> ResourceManager:
    """Get the global resource manager instance"""
    global _resource_manager
    if _resource_manager is None:
        _resource_manager = ResourceManager()
    return _resource_manager


def initialize_resource_manager() -> ResourceManager:
    """Initialize and return the resource manager"""
    global _resource_manager
    _resource_manager = ResourceManager()
    return _resource_manager