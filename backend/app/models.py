from sqlalchemy import Table, Column, Integer, String, Text, DateTime, JSON, MetaData
from sqlalchemy.sql import func
metadata = MetaData()
scans = Table(
    "scans",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("target", String, nullable=False),
    Column("created_at", DateTime, server_default=func.now()),
    Column("report_path", String),
    Column("summary", JSON),
    Column("details", JSON),
)
