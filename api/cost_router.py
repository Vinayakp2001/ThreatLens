"""
API router for cost tracking and benchmarking
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import logging

from .cost_tracker import cost_tracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/costs", tags=["costs"])


@router.get("/summary")
async def get_cost_summary(hours: int = Query(default=24, ge=1, le=720)):
    """
    Get cost summary for the last N hours
    
    Args:
        hours: Number of hours to look back (default: 24, max: 720/30 days)
    """
    try:
        summary = cost_tracker.get_cost_summary(hours=hours)
        return {
            "success": True,
            "data": summary
        }
    except Exception as e:
        logger.error(f"Failed to get cost summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/session")
async def get_session_summary():
    """Get cost summary for the current session"""
    try:
        summary = cost_tracker.get_session_summary()
        return {
            "success": True,
            "data": summary
        }
    except Exception as e:
        logger.error(f"Failed to get session summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/benchmarks")
async def get_benchmark_summary():
    """Get summary of all repository analysis benchmarks"""
    try:
        summary = cost_tracker.get_benchmark_summary()
        return {
            "success": True,
            "data": summary
        }
    except Exception as e:
        logger.error(f"Failed to get benchmark summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pricing")
async def get_pricing_info():
    """Get current pricing information for all providers"""
    from .cost_tracker import OPENAI_PRICING, ANTHROPIC_PRICING, GOOGLE_PRICING
    
    return {
        "success": True,
        "data": {
            "openai": OPENAI_PRICING,
            "anthropic": ANTHROPIC_PRICING,
            "google": GOOGLE_PRICING,
            "note": "Prices are per 1M tokens in USD",
            "last_updated": "2025-01-14"
        }
    }


@router.post("/report")
async def generate_cost_report(hours: int = Query(default=24, ge=1, le=720)):
    """
    Generate and return a formatted cost report
    
    Args:
        hours: Number of hours to include in report
    """
    try:
        summary = cost_tracker.get_cost_summary(hours=hours)
        
        # Format report as text
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append(f"💰 COST REPORT - Last {hours} hours")
        report_lines.append("=" * 80)
        report_lines.append("")
        report_lines.append("📊 Overall Statistics:")
        report_lines.append(f"   Total Cost:     ${summary['total_cost']:.4f}")
        report_lines.append(f"   Total Tokens:   {summary['total_tokens']:,}")
        report_lines.append(f"   Total Requests: {summary['total_requests']}")
        report_lines.append(f"   Avg Cost/Req:   ${summary['avg_cost_per_request']:.6f}")
        report_lines.append(f"   Avg Tokens/Req: {summary['avg_tokens_per_request']:.0f}")
        
        if summary['by_provider']:
            report_lines.append("")
            report_lines.append("🔌 By Provider:")
            for provider, data in summary['by_provider'].items():
                report_lines.append(
                    f"   {provider:15} | Cost: ${data['cost']:.4f} | "
                    f"Tokens: {data['tokens']:,} | Requests: {data['requests']}"
                )
        
        if summary['by_operation']:
            report_lines.append("")
            report_lines.append("⚙️  By Operation:")
            for operation, data in sorted(summary['by_operation'].items(), key=lambda x: x[1]['cost'], reverse=True):
                report_lines.append(
                    f"   {operation:25} | Cost: ${data['cost']:.4f} | Tokens: {data['tokens']:,}"
                )
        
        if summary['by_model']:
            report_lines.append("")
            report_lines.append("🤖 By Model:")
            for model, data in sorted(summary['by_model'].items(), key=lambda x: x[1]['cost'], reverse=True):
                report_lines.append(
                    f"   {model:30} | Cost: ${data['cost']:.4f} | Tokens: {data['tokens']:,}"
                )
        
        report_lines.append("")
        report_lines.append("=" * 80)
        
        report_text = "\n".join(report_lines)
        
        return {
            "success": True,
            "data": {
                "report_text": report_text,
                "summary": summary
            }
        }
    
    except Exception as e:
        logger.error(f"Failed to generate cost report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/estimate")
async def estimate_cost(
    provider: str = Query(..., description="LLM provider (openai, anthropic, google)"),
    model: str = Query(..., description="Model name"),
    input_tokens: int = Query(..., ge=0, description="Estimated input tokens"),
    output_tokens: int = Query(..., ge=0, description="Estimated output tokens")
):
    """
    Estimate cost for a hypothetical request
    
    Args:
        provider: LLM provider
        model: Model name
        input_tokens: Estimated input tokens
        output_tokens: Estimated output tokens
    """
    try:
        costs = cost_tracker.calculate_cost(provider, model, input_tokens, output_tokens)
        
        return {
            "success": True,
            "data": {
                "provider": provider,
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
                "input_cost": costs["input_cost"],
                "output_cost": costs["output_cost"],
                "total_cost": costs["total_cost"],
                "formatted_cost": f"${costs['total_cost']:.6f}"
            }
        }
    
    except Exception as e:
        logger.error(f"Failed to estimate cost: {e}")
        raise HTTPException(status_code=500, detail=str(e))
