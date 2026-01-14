"""
Cost tracking and benchmarking system for LLM API usage
Tracks tokens, costs, and performance metrics for OpenAI and other providers
"""
import logging
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict
import json
from pathlib import Path

logger = logging.getLogger(__name__)


# OpenAI Pricing (as of January 2025)
# Prices are per 1M tokens
OPENAI_PRICING = {
    "gpt-4": {
        "input": 30.00,  # $30 per 1M input tokens
        "output": 60.00  # $60 per 1M output tokens
    },
    "gpt-4-turbo": {
        "input": 10.00,
        "output": 30.00
    },
    "gpt-4-turbo-preview": {
        "input": 10.00,
        "output": 30.00
    },
    "gpt-3.5-turbo": {
        "input": 0.50,  # $0.50 per 1M input tokens
        "output": 1.50  # $1.50 per 1M output tokens
    },
    "gpt-3.5-turbo-16k": {
        "input": 3.00,
        "output": 4.00
    },
    "text-embedding-ada-002": {
        "input": 0.10,  # $0.10 per 1M tokens
        "output": 0.00
    },
    "text-embedding-3-small": {
        "input": 0.02,
        "output": 0.00
    },
    "text-embedding-3-large": {
        "input": 0.13,
        "output": 0.00
    }
}

# Anthropic Pricing
ANTHROPIC_PRICING = {
    "claude-3-opus": {
        "input": 15.00,
        "output": 75.00
    },
    "claude-3-sonnet": {
        "input": 3.00,
        "output": 15.00
    },
    "claude-3-haiku": {
        "input": 0.25,
        "output": 1.25
    }
}

# Google Gemini Pricing
GOOGLE_PRICING = {
    "gemini-1.5-pro": {
        "input": 3.50,
        "output": 10.50
    },
    "gemini-1.5-flash": {
        "input": 0.35,
        "output": 1.05
    }
}


@dataclass
class CostRecord:
    """Individual cost record for an LLM request"""
    timestamp: datetime
    provider: str
    model: str
    operation: str  # e.g., "security_analysis", "threat_modeling", "embedding"
    input_tokens: int
    output_tokens: int
    total_tokens: int
    input_cost: float
    output_cost: float
    total_cost: float
    duration_ms: float
    repository: Optional[str] = None
    success: bool = True
    error: Optional[str] = None


@dataclass
class BenchmarkResult:
    """Benchmark result for repository analysis"""
    repository: str
    start_time: datetime
    end_time: datetime
    total_duration_seconds: float
    total_cost: float
    total_tokens: int
    operations: List[Dict[str, Any]]
    success: bool
    error: Optional[str] = None


class CostTracker:
    """Tracks LLM API costs and provides benchmarking"""
    
    def __init__(self, storage_path: str = "./storage/cost_tracking"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.records: List[CostRecord] = []
        self.benchmarks: List[BenchmarkResult] = []
        
        # Session tracking
        self.session_start = datetime.now()
        self.session_costs = defaultdict(float)
        self.session_tokens = defaultdict(int)
        
        # Load existing records
        self._load_records()
    
    def calculate_cost(self, provider: str, model: str, input_tokens: int, output_tokens: int) -> Dict[str, float]:
        """Calculate cost for a request"""
        pricing = None
        
        if provider == "openai":
            # Find matching model (handle variations)
            for model_key in OPENAI_PRICING:
                if model_key in model.lower():
                    pricing = OPENAI_PRICING[model_key]
                    break
            
            if not pricing:
                # Default to gpt-4 pricing if model not found
                pricing = OPENAI_PRICING["gpt-4"]
                logger.warning(f"Unknown OpenAI model '{model}', using gpt-4 pricing")
        
        elif provider == "anthropic":
            for model_key in ANTHROPIC_PRICING:
                if model_key in model.lower():
                    pricing = ANTHROPIC_PRICING[model_key]
                    break
            
            if not pricing:
                pricing = ANTHROPIC_PRICING["claude-3-sonnet"]
                logger.warning(f"Unknown Anthropic model '{model}', using claude-3-sonnet pricing")
        
        elif provider == "google":
            for model_key in GOOGLE_PRICING:
                if model_key in model.lower():
                    pricing = GOOGLE_PRICING[model_key]
                    break
            
            if not pricing:
                pricing = GOOGLE_PRICING["gemini-1.5-pro"]
                logger.warning(f"Unknown Google model '{model}', using gemini-1.5-pro pricing")
        
        else:
            # Free providers (Hugging Face local models)
            return {
                "input_cost": 0.0,
                "output_cost": 0.0,
                "total_cost": 0.0
            }
        
        # Calculate costs (pricing is per 1M tokens)
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        total_cost = input_cost + output_cost
        
        return {
            "input_cost": input_cost,
            "output_cost": output_cost,
            "total_cost": total_cost
        }
    
    def record_request(
        self,
        provider: str,
        model: str,
        operation: str,
        input_tokens: int,
        output_tokens: int,
        duration_ms: float,
        repository: Optional[str] = None,
        success: bool = True,
        error: Optional[str] = None
    ) -> CostRecord:
        """Record an LLM request with cost calculation"""
        
        total_tokens = input_tokens + output_tokens
        costs = self.calculate_cost(provider, model, input_tokens, output_tokens)
        
        record = CostRecord(
            timestamp=datetime.now(),
            provider=provider,
            model=model,
            operation=operation,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            input_cost=costs["input_cost"],
            output_cost=costs["output_cost"],
            total_cost=costs["total_cost"],
            duration_ms=duration_ms,
            repository=repository,
            success=success,
            error=error
        )
        
        self.records.append(record)
        
        # Update session tracking
        self.session_costs[provider] += costs["total_cost"]
        self.session_tokens[provider] += total_tokens
        
        # Log the cost
        logger.info(
            f"💰 LLM Request Cost | Provider: {provider} | Model: {model} | "
            f"Operation: {operation} | Tokens: {input_tokens}→{output_tokens} | "
            f"Cost: ${costs['total_cost']:.6f} | Duration: {duration_ms:.0f}ms"
        )
        
        # Save periodically
        if len(self.records) % 10 == 0:
            self._save_records()
        
        return record
    
    def start_benchmark(self, repository: str) -> Dict[str, Any]:
        """Start benchmarking a repository analysis"""
        benchmark_id = f"{repository}_{int(time.time())}"
        
        benchmark_data = {
            "id": benchmark_id,
            "repository": repository,
            "start_time": datetime.now(),
            "operations": []
        }
        
        logger.info(f"📊 Starting benchmark for repository: {repository}")
        
        return benchmark_data
    
    def end_benchmark(self, benchmark_data: Dict[str, Any], success: bool = True, error: Optional[str] = None) -> BenchmarkResult:
        """End benchmarking and calculate results"""
        end_time = datetime.now()
        start_time = benchmark_data["start_time"]
        duration = (end_time - start_time).total_seconds()
        
        # Calculate total cost and tokens for this benchmark
        total_cost = 0.0
        total_tokens = 0
        
        for op in benchmark_data["operations"]:
            total_cost += op.get("cost", 0.0)
            total_tokens += op.get("tokens", 0)
        
        result = BenchmarkResult(
            repository=benchmark_data["repository"],
            start_time=start_time,
            end_time=end_time,
            total_duration_seconds=duration,
            total_cost=total_cost,
            total_tokens=total_tokens,
            operations=benchmark_data["operations"],
            success=success,
            error=error
        )
        
        self.benchmarks.append(result)
        
        # Log benchmark results
        logger.info(
            f"📊 Benchmark Complete | Repository: {result.repository} | "
            f"Duration: {duration:.2f}s | Cost: ${total_cost:.4f} | "
            f"Tokens: {total_tokens:,} | Success: {success}"
        )
        
        self._save_benchmarks()
        
        return result
    
    def add_benchmark_operation(self, benchmark_data: Dict[str, Any], operation: str, cost: float, tokens: int, duration_ms: float):
        """Add an operation to the current benchmark"""
        benchmark_data["operations"].append({
            "operation": operation,
            "cost": cost,
            "tokens": tokens,
            "duration_ms": duration_ms,
            "timestamp": datetime.now().isoformat()
        })
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of current session costs"""
        session_duration = (datetime.now() - self.session_start).total_seconds()
        
        total_cost = sum(self.session_costs.values())
        total_tokens = sum(self.session_tokens.values())
        
        return {
            "session_start": self.session_start.isoformat(),
            "session_duration_seconds": session_duration,
            "total_cost": total_cost,
            "total_tokens": total_tokens,
            "costs_by_provider": dict(self.session_costs),
            "tokens_by_provider": dict(self.session_tokens),
            "total_requests": len(self.records)
        }
    
    def get_cost_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get cost summary for the last N hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_records = [r for r in self.records if r.timestamp >= cutoff_time]
        
        if not recent_records:
            return {
                "period_hours": hours,
                "total_cost": 0.0,
                "total_tokens": 0,
                "total_requests": 0,
                "by_provider": {},
                "by_operation": {},
                "by_model": {}
            }
        
        # Aggregate by provider
        by_provider = defaultdict(lambda: {"cost": 0.0, "tokens": 0, "requests": 0})
        by_operation = defaultdict(lambda: {"cost": 0.0, "tokens": 0, "requests": 0})
        by_model = defaultdict(lambda: {"cost": 0.0, "tokens": 0, "requests": 0})
        
        total_cost = 0.0
        total_tokens = 0
        
        for record in recent_records:
            total_cost += record.total_cost
            total_tokens += record.total_tokens
            
            by_provider[record.provider]["cost"] += record.total_cost
            by_provider[record.provider]["tokens"] += record.total_tokens
            by_provider[record.provider]["requests"] += 1
            
            by_operation[record.operation]["cost"] += record.total_cost
            by_operation[record.operation]["tokens"] += record.total_tokens
            by_operation[record.operation]["requests"] += 1
            
            by_model[record.model]["cost"] += record.total_cost
            by_model[record.model]["tokens"] += record.total_tokens
            by_model[record.model]["requests"] += 1
        
        return {
            "period_hours": hours,
            "total_cost": total_cost,
            "total_tokens": total_tokens,
            "total_requests": len(recent_records),
            "by_provider": dict(by_provider),
            "by_operation": dict(by_operation),
            "by_model": dict(by_model),
            "avg_cost_per_request": total_cost / len(recent_records) if recent_records else 0,
            "avg_tokens_per_request": total_tokens / len(recent_records) if recent_records else 0
        }
    
    def get_benchmark_summary(self) -> Dict[str, Any]:
        """Get summary of all benchmarks"""
        if not self.benchmarks:
            return {
                "total_benchmarks": 0,
                "successful_benchmarks": 0,
                "failed_benchmarks": 0,
                "avg_duration_seconds": 0,
                "avg_cost": 0,
                "avg_tokens": 0
            }
        
        successful = [b for b in self.benchmarks if b.success]
        failed = [b for b in self.benchmarks if not b.success]
        
        total_duration = sum(b.total_duration_seconds for b in self.benchmarks)
        total_cost = sum(b.total_cost for b in self.benchmarks)
        total_tokens = sum(b.total_tokens for b in self.benchmarks)
        
        return {
            "total_benchmarks": len(self.benchmarks),
            "successful_benchmarks": len(successful),
            "failed_benchmarks": len(failed),
            "avg_duration_seconds": total_duration / len(self.benchmarks),
            "avg_cost": total_cost / len(self.benchmarks),
            "avg_tokens": total_tokens / len(self.benchmarks),
            "total_cost": total_cost,
            "total_tokens": total_tokens,
            "recent_benchmarks": [
                {
                    "repository": b.repository,
                    "duration_seconds": b.total_duration_seconds,
                    "cost": b.total_cost,
                    "tokens": b.total_tokens,
                    "success": b.success,
                    "timestamp": b.start_time.isoformat()
                }
                for b in sorted(self.benchmarks, key=lambda x: x.start_time, reverse=True)[:10]
            ]
        }
    
    def print_cost_report(self, hours: int = 24):
        """Print a formatted cost report"""
        summary = self.get_cost_summary(hours)
        
        print("\n" + "="*80)
        print(f"💰 COST REPORT - Last {hours} hours")
        print("="*80)
        print(f"\n📊 Overall Statistics:")
        print(f"   Total Cost:     ${summary['total_cost']:.4f}")
        print(f"   Total Tokens:   {summary['total_tokens']:,}")
        print(f"   Total Requests: {summary['total_requests']}")
        print(f"   Avg Cost/Req:   ${summary['avg_cost_per_request']:.6f}")
        print(f"   Avg Tokens/Req: {summary['avg_tokens_per_request']:.0f}")
        
        if summary['by_provider']:
            print(f"\n🔌 By Provider:")
            for provider, data in summary['by_provider'].items():
                print(f"   {provider:15} | Cost: ${data['cost']:.4f} | Tokens: {data['tokens']:,} | Requests: {data['requests']}")
        
        if summary['by_operation']:
            print(f"\n⚙️  By Operation:")
            for operation, data in sorted(summary['by_operation'].items(), key=lambda x: x[1]['cost'], reverse=True):
                print(f"   {operation:25} | Cost: ${data['cost']:.4f} | Tokens: {data['tokens']:,}")
        
        if summary['by_model']:
            print(f"\n🤖 By Model:")
            for model, data in sorted(summary['by_model'].items(), key=lambda x: x[1]['cost'], reverse=True):
                print(f"   {model:30} | Cost: ${data['cost']:.4f} | Tokens: {data['tokens']:,}")
        
        print("\n" + "="*80 + "\n")
    
    def _save_records(self):
        """Save cost records to file"""
        try:
            records_file = self.storage_path / "cost_records.jsonl"
            
            with open(records_file, 'w') as f:
                for record in self.records:
                    record_dict = asdict(record)
                    record_dict['timestamp'] = record.timestamp.isoformat()
                    f.write(json.dumps(record_dict) + '\n')
            
            logger.debug(f"Saved {len(self.records)} cost records")
        
        except Exception as e:
            logger.error(f"Failed to save cost records: {e}")
    
    def _load_records(self):
        """Load cost records from file"""
        try:
            records_file = self.storage_path / "cost_records.jsonl"
            
            if not records_file.exists():
                return
            
            with open(records_file, 'r') as f:
                for line in f:
                    record_dict = json.loads(line)
                    record_dict['timestamp'] = datetime.fromisoformat(record_dict['timestamp'])
                    record = CostRecord(**record_dict)
                    self.records.append(record)
            
            logger.info(f"Loaded {len(self.records)} cost records")
        
        except Exception as e:
            logger.error(f"Failed to load cost records: {e}")
    
    def _save_benchmarks(self):
        """Save benchmarks to file"""
        try:
            benchmarks_file = self.storage_path / "benchmarks.jsonl"
            
            with open(benchmarks_file, 'w') as f:
                for benchmark in self.benchmarks:
                    benchmark_dict = asdict(benchmark)
                    benchmark_dict['start_time'] = benchmark.start_time.isoformat()
                    benchmark_dict['end_time'] = benchmark.end_time.isoformat()
                    f.write(json.dumps(benchmark_dict) + '\n')
            
            logger.debug(f"Saved {len(self.benchmarks)} benchmarks")
        
        except Exception as e:
            logger.error(f"Failed to save benchmarks: {e}")


# Global cost tracker instance
cost_tracker = CostTracker()
