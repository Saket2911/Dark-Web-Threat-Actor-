"""Report generation: CSV, JSON and PDF exports backed by real data."""

import csv
import io
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.provenance import (
    hidden_actor_ids,
    hidden_investigation_ids,
    hidden_source_ids,
    hide_synthetic_evidence,
    hide_synthetic_relationships,
    synthetic_visible,
)
from app.core.time import utcnow
from app.database.session import get_db
from app.models.entities import (
    Actor,
    AnalysisResult,
    AnalystReview,
    Evidence,
    Identifier,
    IntelligenceSource,
    Investigation,
    InvestigationEntity,
    Relationship,
    TimelineEvent,
)

router = APIRouter(prefix="/reports", tags=["reports"])

EXPORT_KINDS = ("actors", "identifiers", "relationships", "evidence", "timeline", "investigations")

CSV_HEADERS = {
    "actors": ["id", "internal_id", "handle", "threat_category", "status", "origin", "external_id", "last_observed"],
    "identifiers": ["id", "actor_id", "id_type", "value", "source", "reliability", "origin", "external_id"],
    "relationships": [
        "id", "source_actor_id", "target_actor_id", "source_type", "source_entity_id",
        "target_type", "target_entity_id", "rel_type", "score", "direct",
        "relationship_classification", "confidence_level", "evidence",
    ],
    "evidence": ["id", "entity_type", "entity_id", "actor_id", "evidence_type", "source", "reliability", "reference", "collected_at"],
    "timeline": ["id", "actor_id", "event_type", "description", "event_date", "source"],
    "investigations": ["id", "title", "status", "created_at", "notes"],
}


def _safe_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in CSV exports."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _rows(db: Session, kind: str, include_synthetic: bool = False) -> List[Dict[str, Any]]:
    show = synthetic_visible(include_synthetic)
    hidden_actors = set() if show else hidden_actor_ids(db)
    hidden_sources = set() if show else set(hidden_source_ids(db))

    if kind == "actors":
        return [
            {
                "id": a.id, "internal_id": a.internal_id, "handle": a.primary_handle,
                "threat_category": a.threat_category, "status": a.investigation_status,
                "origin": a.origin, "external_id": a.external_id,
                "last_observed": a.last_observed,
            }
            for a in db.query(Actor).order_by(Actor.id).all()
            if a.id not in hidden_actors
        ]
    if kind == "identifiers":
        return [
            {
                "id": i.id, "actor_id": i.actor_id, "id_type": i.id_type, "value": i.value,
                "source": i.source, "reliability": i.reliability, "origin": i.origin,
                "external_id": i.external_id,
            }
            for i in db.query(Identifier).order_by(Identifier.id).all()
            if i.actor_id not in hidden_actors
        ]
    if kind == "relationships":
        return [
            {
                "id": r.id,
                "source_actor_id": r.source_actor_id,
                "target_actor_id": r.target_actor_id,
                "source_type": r.source_type,
                "source_entity_id": r.source_entity_id,
                "target_type": r.target_type,
                "target_entity_id": r.target_entity_id,
                "rel_type": r.rel_type,
                "score": r.score,
                "direct": r.direct,
                "relationship_classification": r.relationship_classification,
                "confidence_level": r.confidence_level,
                "evidence": r.evidence,
            }
            for r in hide_synthetic_relationships(
                db.query(Relationship), include_synthetic
            )
            .order_by(Relationship.id)
            .all()
        ]
    if kind == "evidence":
        sources = {s.id: s.name for s in db.query(IntelligenceSource).all()}
        return [
            {
                "id": e.id, "entity_type": e.entity_type, "entity_id": e.entity_id,
                "actor_id": e.actor_id, "evidence_type": e.evidence_type,
                "source": sources.get(e.source_id), "reliability": e.reliability,
                "reference": e.reference, "collected_at": e.collected_at,
            }
            for e in hide_synthetic_evidence(db.query(Evidence), include_synthetic)
            .order_by(Evidence.id)
            .all()
        ]
    if kind == "timeline":
        return [
            {
                "id": t.id, "actor_id": t.actor_id, "event_type": t.event_type,
                "description": t.description, "event_date": t.event_date, "source": t.source,
            }
            for t in db.query(TimelineEvent).order_by(TimelineEvent.id).all()
            if t.actor_id not in hidden_actors
        ]
    if kind == "investigations":
        hidden_investigations = set() if show else hidden_investigation_ids(db)
        return [
            {
                "id": i.id, "title": i.title, "status": i.status,
                "created_at": i.created_at, "notes": i.notes,
            }
            for i in db.query(Investigation).order_by(Investigation.id).all()
            if i.id not in hidden_investigations
        ]
    raise HTTPException(422, f"Unsupported export kind. Valid: {', '.join(EXPORT_KINDS)}")


@router.get("/export/csv")
def export_csv(
    kind: str = "actors",
    include_synthetic: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    if kind not in EXPORT_KINDS:
        raise HTTPException(422, f"Unsupported export kind. Valid: {', '.join(EXPORT_KINDS)}")
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    headers = CSV_HEADERS[kind]
    writer.writerow(headers)
    for row in _rows(db, kind, include_synthetic):
        writer.writerow([_safe_cell(row.get(header)) for header in headers])
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{kind}.csv"'},
    )


@router.get("/export/json")
def export_json(
    kind: str = "actors",
    include_synthetic: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    if kind not in EXPORT_KINDS:
        raise HTTPException(422, f"Unsupported export kind. Valid: {', '.join(EXPORT_KINDS)}")
    payload = {
        "kind": kind,
        "generated_at": utcnow().isoformat(),
        "record_count": 0,
        "synthetic_excluded": not synthetic_visible(include_synthetic),
        "records": _rows(db, kind, include_synthetic),
        "provenance_note": (
            "Records with origin='synthetic' are demonstration data; origin='external' "
            "records come from public feeds; origin='manual' records were entered by analysts."
        ),
    }
    payload["record_count"] = len(payload["records"])
    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{kind}.json"'},
    )


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="SectionHeading", parent=styles["Heading2"], fontSize=12, spaceBefore=12, spaceAfter=4, textColor=colors.HexColor("#0f172a")))
    return styles


def _table(data: List[List[Any]], widths=None, font_size: float = 8):
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), font_size),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5f5")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _paragraph(value: Any, style) -> Paragraph:
    text = "" if value is None else str(value)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(text, style)


def _pdf_response(buffer: io.BytesIO, filename: str) -> Response:
    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/pdf/{actor_id}")
def actor_pdf(
    actor_id: int,
    include_synthetic: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    actor = db.query(Actor).filter(Actor.id == actor_id).first()
    if not actor:
        raise HTTPException(404, "Actor not found")
    if not synthetic_visible(include_synthetic) and actor.id in hidden_actor_ids(db):
        raise HTTPException(404, "Actor not found")

    styles = _styles()
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=letter, title=f"Actor report: {actor.primary_handle}",
        leftMargin=0.75 * inch, rightMargin=0.75 * inch, topMargin=0.7 * inch, bottomMargin=0.7 * inch,
    )
    story: List[Any] = [
        Paragraph("Threat Actor Intelligence Report", styles["Title"]),
        Paragraph(
            f"Generated {utcnow().strftime('%Y-%m-%d %H:%M')} UTC by {user.username}",
            styles["Small"],
        ),
        Spacer(1, 8),
        Paragraph(
            "<b>Analytical product.</b> Observed facts are labelled separately from analytical "
            "hypotheses. Similarity scores are decision support, not proof of identity.",
            styles["Small"],
        ),
        Paragraph("Actor profile", styles["SectionHeading"]),
    ]

    profile_data = [
        ["Field", "Value"],
        ["Internal ID", actor.internal_id],
        ["Primary handle", actor.primary_handle or "-"],
        ["Threat category", actor.threat_category or "-"],
        ["Investigation status", actor.investigation_status or "-"],
        ["Data origin", actor.origin or "manual"],
        ["External ID", actor.external_id or "-"],
        ["Last observed", str(actor.last_observed or "-")],
        ["Notes", actor.notes or "-"],
    ]
    story.append(_table([[ _paragraph(c, styles["Small"]) for c in row] for row in profile_data], widths=[1.6 * inch, 5.2 * inch]))
    story.append(Spacer(1, 6))
    if actor.origin == "synthetic":
        story.append(Paragraph("<i>Synthetic demonstration record - not real-world intelligence.</i>", styles["Small"]))

    story.append(Paragraph("Identifiers (observed facts)", styles["SectionHeading"]))
    if actor.identifiers:
        rows = [["Type", "Value", "Source", "Reliability", "Origin"]]
        for ident in sorted(actor.identifiers, key=lambda i: i.id):
            rows.append([ident.id_type, ident.value, ident.source or "-", f"{ident.reliability:.2f}", ident.origin or "-"])
        story.append(_table([[ _paragraph(c, styles["Small"]) for c in row] for row in rows], widths=[0.9 * inch, 2.8 * inch, 1.3 * inch, 0.9 * inch, 0.9 * inch]))
    else:
        story.append(Paragraph("No identifiers recorded.", styles["Small"]))

    story.append(Paragraph("Handles", styles["SectionHeading"]))
    if actor.handles:
        rows = [["Handle", "Marketplace", "First seen", "Last seen"]]
        for handle in actor.handles:
            rows.append([handle.handle, handle.marketplace or "-", str(handle.first_seen or "-"), str(handle.last_seen or "-")])
        story.append(_table([[ _paragraph(c, styles["Small"]) for c in row] for row in rows], widths=[1.6 * inch, 1.6 * inch, 1.8 * inch, 1.8 * inch]))
    else:
        story.append(Paragraph("No handles recorded.", styles["Small"]))

    story.append(Paragraph("Relationships", styles["SectionHeading"]))
    relationships = (
        db.query(Relationship)
        .filter(
            or_(
                Relationship.source_actor_id == actor.id,
                Relationship.target_actor_id == actor.id,
                (Relationship.source_type == "actor") & (Relationship.source_entity_id == actor.id),
                (Relationship.target_type == "actor") & (Relationship.target_entity_id == actor.id),
            )
        )
        .order_by(Relationship.score.desc())
        .limit(50)
        .all()
    )
    if relationships:
        rows = [["Type", "Other party", "Score", "Basis", "Classification"]]
        for rel in relationships:
            if rel.source_actor_id == actor.id or (rel.source_type == "actor" and rel.source_entity_id == actor.id):
                other_id = rel.target_actor_id or rel.target_entity_id
                other_type = rel.target_type or "actor"
            else:
                other_id = rel.source_actor_id or rel.source_entity_id
                other_type = rel.source_type or "actor"
            other = db.query(Actor).filter(Actor.id == other_id).first() if other_type == "actor" else None
            label = (other.primary_handle or other.internal_id) if other else f"{other_type} {other_id}"
            rows.append([
                rel.rel_type, label, f"{(rel.score or 0):.2f}",
                "direct identifier" if rel.direct else "analytical inference",
                f"{rel.relationship_classification or 'unresolved'}/{rel.confidence_level or 'unverified'}",
            ])
        story.append(_table([[ _paragraph(c, styles["Small"]) for c in row] for row in rows], widths=[1.3 * inch, 1.7 * inch, 0.6 * inch, 1.5 * inch, 1.7 * inch]))
    else:
        story.append(Paragraph("No relationships recorded for this actor.", styles["Small"]))

    story.append(Paragraph("Evidence", styles["SectionHeading"]))
    evidence_rows = (
        db.query(Evidence, IntelligenceSource)
        .outerjoin(IntelligenceSource, Evidence.source_id == IntelligenceSource.id)
        .filter(or_(Evidence.actor_id == actor.id, (Evidence.entity_type == "actor") & (Evidence.entity_id == actor.id)))
        .order_by(Evidence.id)
        .limit(50)
        .all()
    )
    if evidence_rows:
        rows = [["Type", "Source", "Synthetic", "Reliability", "Content"]]
        for evidence, source in evidence_rows:
            rows.append([
                evidence.evidence_type,
                source.name if source else "-",
                "yes" if source and source.is_synthetic else "no",
                f"{evidence.reliability:.2f}",
                (evidence.content or "")[:220],
            ])
        story.append(_table([[ _paragraph(c, styles["Small"]) for c in row] for row in rows], widths=[0.9 * inch, 1.3 * inch, 0.6 * inch, 0.7 * inch, 3.3 * inch]))
    else:
        story.append(Paragraph("No evidence linked.", styles["Small"]))

    story.append(Paragraph("Analysis hypotheses", styles["SectionHeading"]))
    analyses = (
        db.query(AnalysisResult)
        .filter(or_(AnalysisResult.actor_a_id == actor.id, AnalysisResult.actor_b_id == actor.id))
        .order_by(AnalysisResult.created_at.desc())
        .limit(20)
        .all()
    )
    if analyses:
        rows = [["Compared with", "Type", "Score", "Category", "Recorded"]]
        for analysis in analyses:
            other_id = analysis.actor_b_id if analysis.actor_a_id == actor.id else analysis.actor_a_id
            other = db.query(Actor).filter(Actor.id == other_id).first() if other_id else None
            details = analysis.details if isinstance(analysis.details, dict) else {}
            rows.append([
                (other.primary_handle or other.internal_id) if other else (other_id or "-"),
                analysis.analysis_type,
                f"{(analysis.score or 0):.3f}",
                details.get("category", "-"),
                str(analysis.created_at or "-"),
            ])
        story.append(_table([[ _paragraph(c, styles["Small"]) for c in row] for row in rows], widths=[1.7 * inch, 1.2 * inch, 0.7 * inch, 1.4 * inch, 1.8 * inch]))
    else:
        story.append(Paragraph("No analysis results recorded.", styles["Small"]))

    story.append(Paragraph("Limitations", styles["SectionHeading"]))
    for item in (
        "Shared identifiers, writing style and activity patterns are indicators, not identity proof.",
        "Synthetic demonstration records are labelled and must not be treated as real intelligence.",
        "Attribution conclusions require analyst review and corroborating intelligence.",
    ):
        story.append(Paragraph(f"- {item}", styles["Small"]))

    document.build(story)
    buffer.seek(0)
    return _pdf_response(buffer, f"actor_{actor.id}_report.pdf")


@router.get("/pdf/investigation/{investigation_id}")
def investigation_pdf(
    investigation_id: int,
    include_synthetic: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    investigation = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not investigation:
        raise HTTPException(404, "Investigation not found")
    if not synthetic_visible(include_synthetic) and investigation_id in hidden_investigation_ids(db):
        raise HTTPException(404, "Investigation not found")

    styles = _styles()
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=letter, title=f"Investigation {investigation.title}",
        leftMargin=0.75 * inch, rightMargin=0.75 * inch, topMargin=0.7 * inch, bottomMargin=0.7 * inch,
    )
    story: List[Any] = [
        Paragraph("Investigation Report", styles["Title"]),
        Paragraph(f"Generated {utcnow().strftime('%Y-%m-%d %H:%M')} UTC by {user.username}", styles["Small"]),
        Spacer(1, 8),
        Paragraph(f"<b>{investigation.title}</b>", styles["Heading2"]),
        Paragraph(f"Status: {investigation.status} | Created: {investigation.created_at}", styles["Small"]),
        Paragraph(investigation.notes or "No case notes recorded.", styles["Small"]),
        Paragraph("Entities under investigation", styles["SectionHeading"]),
    ]

    member_ids = [
        row[0]
        for row in db.query(InvestigationEntity.actor_id)
        .filter(InvestigationEntity.investigation_id == investigation_id)
        .all()
    ]
    actors = db.query(Actor).filter(Actor.id.in_(member_ids)).all() if member_ids else []
    if actors:
        rows = [["ID", "Handle", "Category", "Status", "Origin"]]
        for actor in actors:
            rows.append([actor.id, actor.primary_handle or actor.internal_id, actor.threat_category or "-", actor.investigation_status, actor.origin])
        story.append(_table([[ _paragraph(c, styles["Small"]) for c in row] for row in rows], widths=[0.6 * inch, 2.2 * inch, 1.6 * inch, 1.2 * inch, 1.2 * inch]))
    else:
        story.append(Paragraph("No entities linked to this investigation.", styles["Small"]))

    story.append(Paragraph("Analyst decisions", styles["SectionHeading"]))
    reviews = (
        db.query(AnalystReview)
        .filter(AnalystReview.investigation_id == investigation_id)
        .order_by(AnalystReview.reviewed_at.desc())
        .all()
    )
    if reviews:
        rows = [["Relationship", "Analyst", "Decision", "Notes", "Reviewed"]]
        for review in reviews:
            rows.append([
                review.relationship_id if review.relationship_id is not None else "-",
                review.analyst or "-",
                review.decision,
                (review.notes or "")[:200],
                str(review.reviewed_at or "-"),
            ])
        story.append(_table([[ _paragraph(c, styles["Small"]) for c in row] for row in rows], widths=[0.9 * inch, 1.1 * inch, 0.9 * inch, 2.6 * inch, 1.3 * inch]))
    else:
        story.append(Paragraph("No analyst decisions recorded yet.", styles["Small"]))

    story.append(Spacer(1, 10))
    story.append(
        Paragraph(
            "All relationships referenced in this report are investigative hypotheses unless "
            "explicitly classified as documented. Review decisions are analyst judgements and "
            "must be re-evaluated when new intelligence arrives.",
            styles["Small"],
        )
    )
    document.build(story)
    buffer.seek(0)
    return _pdf_response(buffer, f"investigation_{investigation.id}_report.pdf")
