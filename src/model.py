from pydantic import BaseModel

class LogBatch(BaseModel):
    source: str
    logs: list[str]

class AlertOut(BaseModel):
    id: int
    rule_name: str
    matched_entity: str | None
    country: str | None = None
    asn: int | None = None
    org: str | None = None
    count: int
    window_seconds: int
    triggered_at: str