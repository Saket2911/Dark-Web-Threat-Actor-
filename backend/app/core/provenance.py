"""Provenance helpers: keep demonstration records out of production views.

Synthetic demonstration rows may exist in a development database (and are used
by isolated tests), but they must never be presented as real intelligence. Read
endpoints call these helpers so the default view contains genuine records only;
``include_synthetic=true`` is an explicit opt-in used by the demo/dev UI, and it
is ignored entirely when ``ENVIRONMENT=production``.

The helpers are deliberately conservative: they hide only records that are
demonstrably demonstration data (synthetic origin, a documented demo seed
handle/value, or a synthetic source). A genuine record with missing fields is
never hidden for being incomplete.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List, Set

from sqlalchemy import and_, or_
from sqlalchemy.orm import Query, Session

from app.core.config import get_settings
from app.models.entities import (
    Actor,
    AnalysisResult,
    Evidence,
    InfrastructureIndicator,
    IntelligenceSource,
    Investigation,
    InvestigationEntity,
    Relationship,
)

# Handles created by the documented demonstration seed. Early seed runs stored
# them as origin='manual'; they are demonstration records, not intelligence, so
# default views hide them until the approval-gated cleanup removes them.
LEGACY_DEMO_HANDLES = {
    "ghostsec",
    "ciphermoth",
    "redpanda",
    "blackpanda",
    "nightshade",
    "darkshade",
    "migrator",
    "alpha1",
    "beta2",
    "conflict_a",
    "conflict_b",
    "testactor",
}


def synthetic_visible(include_synthetic: bool) -> bool:
    """Synthetic records are opt-in, and never in a production environment."""

    return bool(include_synthetic) and get_settings().environment != "production"


def legacy_demo_actor_ids(db: Session) -> Set[int]:
    """Mislabelled demonstration actors from early seed runs.

    Only records that cannot be mistaken for analyst intelligence qualify: a
    documented demo handle, no external identifier, and no evidence from a real
    external source.
    """

    candidates = (
        db.query(Actor)
        .filter(
            or_(Actor.origin.is_(None), Actor.origin == "manual"),
            Actor.external_id.is_(None),
        )
        .all()
    )
    hidden: Set[int] = set()
    for actor in candidates:
        if (actor.primary_handle or "").strip().lower() not in LEGACY_DEMO_HANDLES:
            continue
        external = (
            db.query(Evidence.id)
            .join(IntelligenceSource, Evidence.source_id == IntelligenceSource.id)
            .filter(
                or_(
                    Evidence.actor_id == actor.id,
                    (Evidence.entity_type == "actor") & (Evidence.entity_id == actor.id),
                ),
                IntelligenceSource.is_synthetic.is_(False),
            )
            .first()
        )
        if external is None:
            hidden.add(actor.id)
    return hidden


def hidden_actor_ids(db: Session) -> Set[int]:
    """Actors hidden from default views: synthetic plus legacy demo rows."""

    synthetic = {row[0] for row in db.query(Actor.id).filter(Actor.origin == "synthetic").all()}
    return synthetic | legacy_demo_actor_ids(db)


LEGACY_DEMO_INDICATOR_VALUES = {
    "sha256:abcd1234",
    "example-market.com",
    "203.0.113.10",
}


def hidden_source_ids(db: Session) -> List[int]:
    return [
        row[0]
        for row in db.query(IntelligenceSource.id)
        .filter(IntelligenceSource.is_synthetic.is_(True))
        .all()
    ]


def synthetic_source_names(db: Session) -> Set[str]:
    return {
        row[0]
        for row in db.query(IntelligenceSource.name)
        .filter(IntelligenceSource.is_synthetic.is_(True))
        .all()
        if row[0]
    }


def hidden_indicator_ids(db: Session) -> Set[int]:
    """Indicators that belong to the demonstration dataset."""

    conditions = [
        InfrastructureIndicator.origin == "synthetic",
        InfrastructureIndicator.value.in_(LEGACY_DEMO_INDICATOR_VALUES),
    ]
    names = synthetic_source_names(db)
    if names:
        conditions.append(InfrastructureIndicator.source.in_(names))
    return {
        row[0]
        for row in db.query(InfrastructureIndicator.id)
        .filter(or_(*conditions))
        .all()
    }


def hidden_investigation_ids(db: Session) -> Set[int]:
    """Cases whose every member is a hidden demonstration actor.

    A case with no members (or with at least one genuine member) stays visible:
    hiding a genuine analyst case because it is empty would lose real work.
    """

    hidden = hidden_actor_ids(db)
    if not hidden:
        return set()
    members: dict[int, list[int]] = defaultdict(list)
    for investigation_id, actor_id in db.query(
        InvestigationEntity.investigation_id, InvestigationEntity.actor_id
    ).all():
        if investigation_id is not None and actor_id is not None:
            members[investigation_id].append(int(actor_id))
    return {
        investigation_id
        for investigation_id, actor_ids in members.items()
        if actor_ids and all(actor_id in hidden for actor_id in actor_ids)
    }


def hide_demo_indicators(query: Query, include_synthetic: bool) -> Query:
    if synthetic_visible(include_synthetic):
        return query
    conditions = [
        InfrastructureIndicator.origin.is_(None),
        InfrastructureIndicator.origin != "synthetic",
    ]
    names = synthetic_source_names(query.session)
    if names:
        conditions.append(
            or_(
                InfrastructureIndicator.source.is_(None),
                ~InfrastructureIndicator.source.in_(names),
            )
        )
    return query.filter(
        or_(*conditions) if len(conditions) > 1 else conditions[0],
        ~InfrastructureIndicator.value.in_(LEGACY_DEMO_INDICATOR_VALUES),
    )


def hide_synthetic_actors(query: Query, include_synthetic: bool) -> Query:
    if synthetic_visible(include_synthetic):
        return query
    hidden = hidden_actor_ids(query.session)
    if not hidden:
        return query
    return query.filter(~Actor.id.in_(hidden))


def hide_synthetic_evidence(query: Query, include_synthetic: bool) -> Query:
    if synthetic_visible(include_synthetic):
        return query
    session = query.session
    conditions = []
    actors = hidden_actor_ids(session)
    if actors:
        conditions.append(or_(Evidence.actor_id.is_(None), ~Evidence.actor_id.in_(actors)))
        # NULL entity types (unlinked reports) are genuine records and stay.
        conditions.append(
            or_(
                Evidence.entity_type.is_(None),
                Evidence.entity_type != "actor",
                Evidence.entity_id.is_(None),
                ~Evidence.entity_id.in_(actors),
            )
        )
    sources = hidden_source_ids(session)
    if sources:
        conditions.append(or_(Evidence.source_id.is_(None), ~Evidence.source_id.in_(sources)))
    indicators = hidden_indicator_ids(session)
    if indicators:
        conditions.append(
            or_(
                Evidence.entity_type.is_(None),
                Evidence.entity_type != "indicator",
                Evidence.entity_id.is_(None),
                ~Evidence.entity_id.in_(indicators),
            )
        )
    return query.filter(and_(*conditions)) if conditions else query


def _visible_actor_endpoint(type_column, entity_column, legacy_column, hidden):
    """An edge endpoint is visible unless it is a hidden actor.

    Legacy rows store ``source_type``/``target_type`` as NULL and keep the actor
    id only in ``source_actor_id``/``target_actor_id``, so both columns are
    checked. NULL identifiers must not exclude a row by themselves.
    """

    return or_(
        and_(type_column.is_not(None), type_column != "actor"),
        and_(
            or_(type_column.is_(None), type_column == "actor"),
            or_(entity_column.is_(None), ~entity_column.in_(hidden)),
            or_(legacy_column.is_(None), ~legacy_column.in_(hidden)),
        ),
    )


def hide_synthetic_relationships(query: Query, include_synthetic: bool) -> Query:
    """Remove edges that touch a hidden actor or demonstration indicator."""

    if synthetic_visible(include_synthetic):
        return query
    session = query.session
    conditions = []
    actors = hidden_actor_ids(session)
    if actors:
        conditions.append(
            _visible_actor_endpoint(
                Relationship.source_type,
                Relationship.source_entity_id,
                Relationship.source_actor_id,
                actors,
            )
        )
        conditions.append(
            _visible_actor_endpoint(
                Relationship.target_type,
                Relationship.target_entity_id,
                Relationship.target_actor_id,
                actors,
            )
        )
    indicators = hidden_indicator_ids(session)
    if indicators:
        conditions.append(
            or_(
                Relationship.source_type.is_(None),
                Relationship.source_type != "indicator",
                Relationship.source_entity_id.is_(None),
                ~Relationship.source_entity_id.in_(indicators),
            )
        )
        conditions.append(
            or_(
                Relationship.target_type.is_(None),
                Relationship.target_type != "indicator",
                Relationship.target_entity_id.is_(None),
                ~Relationship.target_entity_id.in_(indicators),
            )
        )
    return query.filter(and_(*conditions)) if conditions else query


def hide_synthetic_analyses(query: Query, include_synthetic: bool) -> Query:
    """Hide analyses that compare a hidden demonstration actor."""

    if synthetic_visible(include_synthetic):
        return query
    hidden = hidden_actor_ids(query.session)
    if not hidden:
        return query
    # Unattributed inference records have NULL actor ids and remain visible.
    return query.filter(
        or_(AnalysisResult.actor_a_id.is_(None), ~AnalysisResult.actor_a_id.in_(hidden)),
        or_(AnalysisResult.actor_b_id.is_(None), ~AnalysisResult.actor_b_id.in_(hidden)),
    )


def hide_synthetic_investigations(query: Query, include_synthetic: bool) -> Query:
    """Hide cases whose only members are hidden demonstration actors."""

    if synthetic_visible(include_synthetic):
        return query
    hidden = hidden_investigation_ids(query.session)
    if not hidden:
        return query
    return query.filter(~Investigation.id.in_(hidden))


def hide_synthetic_sources(query: Query, include_synthetic: bool) -> Query:
    if synthetic_visible(include_synthetic):
        return query
    return query.filter(
        or_(IntelligenceSource.is_synthetic.is_(False), IntelligenceSource.is_synthetic.is_(None))
    )
