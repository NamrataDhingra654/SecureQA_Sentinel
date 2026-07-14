from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, inspect, text, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import hashlib
import json

GENESIS_HASH = "0" * 64  # previous_hash for the very first scan in the chain

# This creates a file called scans.db in your project folder — that's your entire database
engine = create_engine('sqlite:///scans.db')
Base = declarative_base()


class Scan(Base):
    __tablename__ = 'scans'

    id = Column(Integer, primary_key=True)
    target_url = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    findings_json = Column(Text)       # raw findings stored as JSON text
    total_findings = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Legacy single-slot report cache columns — superseded by the Report
    # table below (which caches one report PER backend), kept here only so
    # the migration path from earlier versions of this app doesn't break.
    report_text = Column(Text, nullable=True)
    report_generated_at = Column(DateTime, nullable=True)
    report_backend = Column(String, nullable=True)

    # Tamper-evident audit trail — hash chain, added for integrity verification
    record_hash = Column(String, nullable=True)     # SHA-256 of this record + previous_hash
    previous_hash = Column(String, nullable=True)    # record_hash of the prior scan in the chain


class Report(Base):
    """
    One cached AI report PER (scan, backend) pair — so Ollama's report and
    Groq's report for the same scan can both exist at once, independently,
    instead of one overwriting the other.
    """
    __tablename__ = 'reports'

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, nullable=False)
    backend = Column(String, nullable=False)   # "ollama" or "groq"
    report_text = Column(Text)
    generated_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint('scan_id', 'backend', name='uq_scan_backend'),)


def _migrate():
    """
    Lightweight migration: if scans.db already exists from before the
    report_text / report_generated_at columns were added, ALTER TABLE
    to add them. create_all() only creates missing TABLES, not missing
    COLUMNS on existing tables, so this is needed on top of it.
    """
    inspector = inspect(engine)
    if 'scans' not in inspector.get_table_names():
        return  # fresh DB, create_all() below will make the table correctly

    existing_columns = {c['name'] for c in inspector.get_columns('scans')}
    with engine.connect() as conn:
        if 'report_text' not in existing_columns:
            conn.execute(text('ALTER TABLE scans ADD COLUMN report_text TEXT'))
            print("Migrated: added report_text column")
        if 'report_generated_at' not in existing_columns:
            conn.execute(text('ALTER TABLE scans ADD COLUMN report_generated_at DATETIME'))
            print("Migrated: added report_generated_at column")
        if 'report_backend' not in existing_columns:
            conn.execute(text('ALTER TABLE scans ADD COLUMN report_backend VARCHAR'))
            print("Migrated: added report_backend column")
        if 'record_hash' not in existing_columns:
            conn.execute(text('ALTER TABLE scans ADD COLUMN record_hash VARCHAR'))
            print("Migrated: added record_hash column")
        if 'previous_hash' not in existing_columns:
            conn.execute(text('ALTER TABLE scans ADD COLUMN previous_hash VARCHAR'))
            print("Migrated: added previous_hash column")
        conn.commit()


# Create table if it doesn't exist, then patch it with any missing columns
Base.metadata.create_all(engine)
_migrate()

Session = sessionmaker(bind=engine)


def to_iso_utc(dt):
    """
    Format a naive UTC datetime (as produced by datetime.utcnow(), which is
    what this whole file uses) as an ISO string with an explicit 'Z' suffix.

    Without the 'Z', JS's `new Date(...)` assumes the string is already in
    the browser's LOCAL timezone and doesn't convert it — so anyone not in
    UTC sees times offset by their timezone difference. This makes the UTC-
    ness explicit so the frontend converts to local time correctly.
    """
    if dt is None:
        return None
    return dt.isoformat() + "Z"


def _compute_hash(scan_id, target_url, timestamp, findings_json, previous_hash):
    """
    SHA-256 of this record's core content chained to the previous record's
    hash. Changing target_url, timestamp, or a single findings byte after
    the fact — or deleting/reordering a row — breaks the chain and is
    detectable by verify_chain().
    """
    payload = f"{scan_id}|{target_url}|{timestamp}|{findings_json}|{previous_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def save_scan(target_url, findings, total_findings=None, high_count=None,
              medium_count=None, low_count=None, info_count=None):
    """
    Takes the target URL and the list of findings from ZAP, saves everything
    to the database.

    Severity counts can be passed in pre-computed (this is what app.py does,
    using its own case-insensitive _severity_counts() which also folds
    "Informational" into info correctly). If they're not passed in, this
    function falls back to counting them itself.
    """
    session = Session()

    if total_findings is None or high_count is None or medium_count is None \
            or low_count is None or info_count is None:
        counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in findings:
            risk = f.get('risk', 'Informational')
            if risk in counts:
                counts[risk] += 1
        total_findings = len(findings)
        high_count = counts["High"]
        medium_count = counts["Medium"]
        low_count = counts["Low"]
        info_count = counts["Informational"]

    new_scan = Scan(
        target_url=target_url,
        findings_json=json.dumps(findings),
        total_findings=total_findings,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
    )

    session.add(new_scan)
    session.commit()   # commit first so id/timestamp are assigned by the DB

    scan_id = new_scan.id

    # ── Chain this record's hash to the previous one ────────────────────────
    prior = (
        session.query(Scan)
        .filter(Scan.id < scan_id)
        .order_by(Scan.id.desc())
        .first()
    )
    # If there's no prior scan, or the prior scan predates this feature
    # (legacy row with no hash), the chain restarts cleanly from genesis here.
    previous_hash = prior.record_hash if (prior and prior.record_hash) else GENESIS_HASH

    record_hash = _compute_hash(
        scan_id=scan_id,
        target_url=new_scan.target_url,
        timestamp=new_scan.timestamp,
        findings_json=new_scan.findings_json,
        previous_hash=previous_hash,
    )

    new_scan.previous_hash = previous_hash
    new_scan.record_hash = record_hash
    session.commit()
    session.close()

    print(f"Scan saved to database with ID: {scan_id}")
    return scan_id


def get_scan(scan_id):
    """Fetch a single scan by ID."""
    session = Session()
    scan = session.query(Scan).filter(Scan.id == scan_id).first()
    session.close()
    return scan


def get_all_scans():
    """Fetch all scans, most recent first."""
    session = Session()
    scans = session.query(Scan).order_by(Scan.timestamp.desc()).all()
    session.close()
    return scans


def save_report(scan_id, report_text, backend):
    """
    Cache a generated AI report for a specific (scan, backend) pair.
    Ollama's report and Groq's report for the same scan are stored
    independently — generating one never overwrites the other.
    """
    session = Session()
    existing = (
        session.query(Report)
        .filter(Report.scan_id == scan_id, Report.backend == backend)
        .first()
    )
    if existing:
        existing.report_text = report_text
        existing.generated_at = datetime.utcnow()
    else:
        session.add(Report(
            scan_id=scan_id,
            backend=backend,
            report_text=report_text,
            generated_at=datetime.utcnow(),
        ))
    session.commit()
    session.close()


def verify_chain():
    """
    Walk every scan in ID order and recompute each hash from its stored
    content to confirm nothing has been altered after the fact, and that
    the previous_hash pointers still form an unbroken chain.

    Returns:
      {
        "valid": bool,               # True if no tampering/breaks detected
        "total_scans": int,
        "verified_count": int,       # scans actually covered by the chain
        "legacy_count": int,         # scans saved before this feature existed
        "issues": [
          { "scan_id": 3, "type": "tampered" | "chain_broken", "detail": "..." }
        ]
      }
    """
    session = Session()
    scans = session.query(Scan).order_by(Scan.id.asc()).all()
    session.close()

    issues = []
    verified_count = 0
    legacy_count = 0
    last_hash = None  # hash of the most recent record that WAS covered by the chain

    for scan in scans:
        if not scan.record_hash:
            legacy_count += 1
            continue  # saved before the audit trail feature existed — not verifiable

        expected_hash = _compute_hash(
            scan_id=scan.id,
            target_url=scan.target_url,
            timestamp=scan.timestamp,
            findings_json=scan.findings_json,
            previous_hash=scan.previous_hash,
        )

        if expected_hash != scan.record_hash:
            issues.append({
                "scan_id": scan.id,
                "type": "tampered",
                "detail": "Stored hash does not match recomputed hash — "
                          "target_url, timestamp, or findings_json was modified after saving.",
            })
        elif last_hash is not None and scan.previous_hash != last_hash:
            issues.append({
                "scan_id": scan.id,
                "type": "chain_broken",
                "detail": "previous_hash does not match the prior verified record's hash — "
                          "a record may have been deleted or reordered.",
            })
        else:
            verified_count += 1

        last_hash = scan.record_hash

    return {
        "valid": len(issues) == 0,
        "total_scans": len(scans),
        "verified_count": verified_count,
        "legacy_count": legacy_count,
        "issues": issues,
    }


def get_report(scan_id, backend):
    """
    Return (report_text, report_generated_at) for a specific (scan, backend)
    pair, or (None, None) if that combination hasn't been generated yet.
    """
    session = Session()
    r = (
        session.query(Report)
        .filter(Report.scan_id == scan_id, Report.backend == backend)
        .first()
    )
    session.close()
    if r is None:
        return None, None
    return r.report_text, r.generated_at