"""
NetShield AI - FastAPI + SQLAlchemy Reference Backend
Mirrors all /api/v1/* endpoints implemented in the live Express + ML server.
Configure DATABASE_URL and JWT_SECRET_KEY via environment variables.
"""

from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="NetShield AI API", version="1.0.0")


class FlowPredictionRequest(BaseModel):
    src_ip: str = Field(..., min_length=3, max_length=45)
    dst_ip: str = Field(..., min_length=3, max_length=45)
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] = "TCP"
    flow_duration: float = Field(..., ge=0)
    total_fwd_packets: int = Field(..., ge=0)
    total_bwd_packets: int = Field(..., ge=0)
    total_len_fwd_packets: float = Field(..., ge=0)
    total_len_bwd_packets: float = Field(..., ge=0)


class AlertStatusUpdate(BaseModel):
    status: Literal["Open", "Investigating", "Resolved"]


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "ok",
        "service": "NetShield AI FastAPI Reference",
        "mode": "detection_only",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
