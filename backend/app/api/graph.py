"""Relationship graph API.

The graph is assembled from stored data only:

* actor nodes from ``actors``
* identifier nodes from ``identifiers`` (one node per canonical value)
* infrastructure indicator nodes from ``infrastructure_indicators``
* edges from ``relationships`` (persisted, with evidence and classification)
* ``HAS_IDENTIFIER`` ownership edges synthesised from the identifier table

Optional filters support the explorer UI: actor focus with neighbourhood
depth, relation-type filter, minimum score and free-text search.
"""

import hashlib
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set

import networkx as nx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, require_admin
from app.database.session import get_db
from app.models.entities import (
    Actor,
    AnalystReview,
    Campaign,
    Identifier,
    InfrastructureIndicator,
    Malware,
    Relationship,
    Tactic,
    Technique,
    Tool,
)
from app.schemas.schemas import RelationshipIn
from app.services.audit import audit
from app.services.relationship_engine import (
    build_direct_relationships,
    build_inferred_relationships,
    relationship_statistics,
)
from app.services.relationship_validator import (
    RelationshipValidationError,
    create_relationship,
)

router = APIRouter(prefix="/graph", tags=["graph"])

ENTITY_MODELS = {
    "actor": (Actor, lambda e: e.primary_handle or e.internal_id),
    "campaign": (Campaign, lambda e: e.name),
    "malware": (Malware, lambda e: e.name),
    "tool": (Tool, lambda e: e.name),
    "technique": (Technique, lambda e: e.name),
    "tactic": (Tactic, lambda e: e.name),
    "indicator": (InfrastructureIndicator, lambda e: e.value),
}


def _identifier_node_id(id_type: str, value: str) -> str:
    digest = hashlib.sha1(f"{id_type}:{value}".encode("utf-8")).hexdigest()[:12]
    return f"identifier_{digest}"


def _actor_node(actor: Actor) -> dict:
    return {
        "data": {
            "id": f"actor_{actor.id}",
            "label": actor.primary_handle or actor.internal_id,
            "type": "actor",
            "internal_id": actor.internal_id,
            "category": actor.threat_category,
            "status": actor.investigation_status,
            "origin": actor.origin,
        }
    }


def _resolve_entity_node(db: Session, entity_type: str, entity_id: int) -> Optional[dict]:
    info = ENTITY_MODELS.get(entity_type)
    if not info:
        return None
    model, labeler = info
    entity = db.query(model).filter(model.id == entity_id).first()
    if not entity:
        return None
    data = {
        "id": f"{entity_type}_{entity_id}",
        "label": labeler(entity),
        "type": entity_type,
        "origin": getattr(entity, "origin", None),
    }
    if entity_type == "actor":
        data.update(
            {
                "internal_id": entity.internal_id,
                "category": entity.threat_category,
                "status": entity.investigation_status,
            }
        )
    elif entity_type == "indicator":
        data.update({"value": entity.value, "source": entity.source})
    elif entity_type in ("campaign", "malware", "tool", "technique", "tactic"):
        data.update({"external_id": getattr(entity, "external_id", None)})
    return {"data": data}


def _relationship_endpoints(rel: Relationship):
    source_id = rel.source_actor_id or (
        rel.source_entity_id if rel.source_type == "actor" else None
    )
    target_id = rel.target_actor_id or (
        rel.target_entity_id if rel.target_type == "actor" else None
    )
    source_type = rel.source_type or ("actor" if source_id else None)
    target_type = rel.target_type or ("actor" if target_id else None)
    return source_type, source_id, target_type, target_id


def _collect_actor_ids_for_focus(db: Session, actors: List[Actor], focus: int, depth: int) -> Set[int]:
    """Breadth-first neighbourhood of ``focus`` over actor-to-actor links."""
    adjacency: Dict[int, Set[int]] = defaultdict(set)
    for rel in db.query(Relationship).all():
        s_type, s_id, t_type, t_id = _relationship_endpoints(rel)
        if s_type == "actor" and t_type == "actor" and s_id and t_id:
            adjacency[int(s_id)].add(int(t_id))
            adjacency[int(t_id)].add(int(s_id))
    allowed = {focus}
    frontier = deque([(focus, 0)])
    while frontier:
        node, level = frontier.popleft()
        if level >= depth:
            continue
        for neighbour in adjacency.get(node, set()):
            if neighbour not in allowed:
                allowed.add(neighbour)
                frontier.append((neighbour, level + 1))
    return allowed


@router.get("/data")
def graph_data(
    actor_id: Optional[int] = Query(None, description="Focus on one actor and its neighbourhood"),
    depth: int = Query(1, ge=0, le=3),
    include_identifiers: bool = True,
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    rel_types: Optional[str] = Query(None, description="Comma separated relationship types"),
    q: Optional[str] = Query(None, description="Search node labels"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    nodes: List[dict] = []
    edges: List[dict] = []
    seen_nodes: Set[str] = set()
    seen_edges: Set[tuple] = set()

    actors = db.query(Actor).order_by(Actor.id).all()
    actors_by_id = {a.id: a for a in actors}

    if actor_id is not None:
        if actor_id not in actors_by_id:
            raise HTTPException(404, "Actor not found")
        allowed_actor_ids = _collect_actor_ids_for_focus(db, actors, actor_id, depth)
    else:
        allowed_actor_ids = set(actors_by_id)

    wanted_types = (
        {t.strip().upper() for t in rel_types.split(",") if t.strip()} if rel_types else None
    )
    search = (q or "").strip().lower()
    owner_map: Dict[str, List[dict]] = defaultdict(list)
    identifier_nodes: Dict[str, dict] = {}

    include_identifier_edges = include_identifiers and (
        wanted_types is None or "HAS_IDENTIFIER" in wanted_types
    )

    if include_identifiers:
        for identifier in db.query(Identifier).order_by(Identifier.id).all():
            if identifier.actor_id not in allowed_actor_ids:
                continue
            node_id = _identifier_node_id(identifier.id_type, str(identifier.value))
            if node_id not in identifier_nodes:
                identifier_nodes[node_id] = {
                    "data": {
                        "id": node_id,
                        "label": str(identifier.value),
                        "type": "identifier",
                        "identifier_type": identifier.id_type,
                        "value": str(identifier.value),
                        "origin": identifier.origin,
                    }
                }
            owner_map[node_id].append(
                {
                    "actor_id": identifier.actor_id,
                    "handle": (actors_by_id.get(identifier.actor_id).primary_handle
                               if actors_by_id.get(identifier.actor_id) else None),
                    "source": identifier.source,
                    "reliability": identifier.reliability,
                }
            )
            if not include_identifier_edges:
                continue
            key = (f"actor_{identifier.actor_id}", node_id, "HAS_IDENTIFIER")
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(
                {
                    "data": {
                        "id": f"has_{identifier.id}",
                        "source": f"actor_{identifier.actor_id}",
                        "target": node_id,
                        "label": "HAS_IDENTIFIER",
                        "direct": True,
                        "synthetic_edge": True,
                        "evidence": (
                            f"{identifier.actor_id} is recorded with "
                            f"{identifier.id_type} {identifier.value} "
                            f"(source: {identifier.source or 'unknown'})"
                        ),
                        "relationship_classification": "documented",
                        "confidence_level": "limited",
                        "score": 1.0,
                    }
                }
            )

    for identifier in db.query(Identifier).all():
        if identifier.actor_id not in allowed_actor_ids:
            continue
        node_id = _identifier_node_id(identifier.id_type, str(identifier.value))
        if node_id in identifier_nodes and len(owner_map.get(node_id, [])) > 1:
            identifier_nodes[node_id]["data"]["owners"] = owner_map[node_id]

    for actor in actors:
        if actor.id not in allowed_actor_ids:
            continue
        if search and search not in (actor.primary_handle or "").lower() and search not in actor.internal_id.lower():
            continue
        node = _actor_node(actor)
        if node["data"]["id"] not in seen_nodes:
            seen_nodes.add(node["data"]["id"])
            nodes.append(node)

    if include_identifiers:
        for node_id, node in identifier_nodes.items():
            if search and search not in str(node["data"]["label"]).lower():
                continue
            if node_id not in seen_nodes:
                seen_nodes.add(node_id)
                nodes.append(node)

    for rel in db.query(Relationship).order_by(Relationship.id).all():
        if wanted_types and (rel.rel_type or "").upper() not in wanted_types:
            continue
        if (rel.score or 0.0) < min_score:
            continue
        s_type, s_id, t_type, t_id = _relationship_endpoints(rel)
        if not s_id or not t_id:
            continue
        if s_type == "actor" and int(s_id) not in allowed_actor_ids:
            continue
        if t_type == "actor" and int(t_id) not in allowed_actor_ids:
            continue

        source_node = f"actor_{s_id}" if s_type == "actor" else f"{s_type}_{s_id}"
        target_node = f"actor_{t_id}" if t_type == "actor" else f"{t_type}_{t_id}"

        for entity_type, entity_id, node_id in ((s_type, s_id, source_node), (t_type, t_id, target_node)):
            if node_id in seen_nodes:
                continue
            resolved = _resolve_entity_node(db, entity_type, int(entity_id))
            if resolved is None:
                break
            if search and search not in str(resolved["data"].get("label", "")).lower():
                continue
            seen_nodes.add(node_id)
            nodes.append(resolved)

        if source_node not in seen_nodes or target_node not in seen_nodes:
            continue

        key = (source_node, target_node, rel.rel_type, rel.id)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        edges.append(
            {
                "data": {
                    "id": f"rel_{rel.id}",
                    "relationship_id": rel.id,
                    "source": source_node,
                    "target": target_node,
                    "label": rel.rel_type,
                    "score": rel.score,
                    "direct": rel.direct,
                    "evidence": rel.evidence or "",
                    "relationship_classification": rel.relationship_classification,
                    "confidence_level": rel.confidence_level,
                    "source_confidence": rel.source_confidence,
                    "created_at": rel.created_at.isoformat() if rel.created_at else None,
                }
            }
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "actor_nodes": sum(1 for n in nodes if n["data"]["type"] == "actor"),
            "identifier_nodes": sum(1 for n in nodes if n["data"]["type"] == "identifier"),
            "indicator_nodes": sum(1 for n in nodes if n["data"]["type"] == "indicator"),
            "edges": len(edges),
            "direct_edges": sum(1 for e in edges if e["data"].get("direct")),
            "inferred_edges": sum(1 for e in edges if e["data"].get("direct") is False),
            "focus_actor_id": actor_id,
        },
    }


@router.get("/stats")
def graph_stats(db: Session = Depends(get_db), user=Depends(get_current_user)):
    stats = relationship_statistics(db)
    stats["actors"] = db.query(Actor).count()
    stats["identifiers"] = db.query(Identifier).count()
    stats["indicators"] = db.query(InfrastructureIndicator).count()
    return stats


@router.get("/relationships/{relationship_id}")
def relationship_detail(relationship_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    rel = db.query(Relationship).filter(Relationship.id == relationship_id).first()
    if not rel:
        raise HTTPException(404, "Relationship not found")
    s_type, s_id, t_type, t_id = _relationship_endpoints(rel)
    source = _resolve_entity_node(db, s_type, int(s_id)) if s_type and s_id else None
    target = _resolve_entity_node(db, t_type, int(t_id)) if t_type and t_id else None
    reviews = (
        db.query(AnalystReview)
        .filter(AnalystReview.relationship_id == rel.id)
        .order_by(AnalystReview.reviewed_at.desc())
        .all()
    )
    return {
        "id": rel.id,
        "rel_type": rel.rel_type,
        "score": rel.score,
        "direct": rel.direct,
        "evidence": rel.evidence,
        "relationship_classification": rel.relationship_classification,
        "confidence_level": rel.confidence_level,
        "source_confidence": rel.source_confidence,
        "created_at": rel.created_at,
        "source": source["data"] if source else None,
        "target": target["data"] if target else None,
        "reviews": [
            {
                "id": review.id,
                "analyst": review.analyst,
                "decision": review.decision,
                "notes": review.notes,
                "reviewed_at": review.reviewed_at,
            }
            for review in reviews
        ],
        "interpretation": (
            "Direct identifier match: a documented shared fact, still not proof of a shared operator."
            if rel.direct
            else "Analytical similarity: an investigative hypothesis only."
        ),
    }


@router.post("/build")
def build_relationships(db: Session = Depends(get_db), user=Depends(get_current_user)):
    stats = build_direct_relationships(db)
    audit(db, user.username, "build_relationships", str(stats))
    return {
        **stats,
        "direct_created": stats.get("created", 0),
        "message": (
            "Relationship build complete. Links are created only from directly observed "
            "shared identifiers and matching infrastructure."
        ),
    }


@router.post("/infer")
def infer_personas(
    threshold: Optional[float] = Query(None, ge=0.0, le=1.0),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    stats = build_inferred_relationships(db, threshold=threshold)
    audit(db, user.username, "infer_relationships", str(stats))
    return {
        **stats,
        "inferred": stats.get("created", 0),
        "message": (
            "Inferred links come from stored analytical similarity results at or above the "
            "threshold. They are hypotheses, not identity confirmations."
        ),
    }


@router.post("/relationships")
def create_manual_relationship(
    body: RelationshipIn,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    if body.source_actor_id == body.target_actor_id:
        raise HTTPException(422, "Self-referencing relationships are not permitted")
    existing = (
        db.query(Relationship)
        .filter(
            or_(
                (Relationship.source_actor_id == body.source_actor_id)
                & (Relationship.target_actor_id == body.target_actor_id),
                (Relationship.source_actor_id == body.target_actor_id)
                & (Relationship.target_actor_id == body.source_actor_id),
            ),
            Relationship.rel_type == body.rel_type,
        )
        .first()
    )
    if existing:
        raise HTTPException(409, f"Relationship already exists (id {existing.id})")
    try:
        rel = create_relationship(
            db=db,
            source_type="actor",
            source_entity_id=body.source_actor_id,
            target_type="actor",
            target_entity_id=body.target_actor_id,
            rel_type=body.rel_type,
            evidence=body.evidence,
            score=body.score,
            relationship_classification=body.relationship_classification,
            confidence_level=body.confidence_level,
            direct=False,
        )
    except RelationshipValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit(db, user.username, "create_relationship", f"relationship {rel.id}")
    return {"id": rel.id}


@router.delete("/relationships/{relationship_id}")
def delete_relationship(relationship_id: int, db: Session = Depends(get_db), user=Depends(require_admin)):
    rel = db.query(Relationship).filter(Relationship.id == relationship_id).first()
    if not rel:
        raise HTTPException(404, "Relationship not found")
    db.query(AnalystReview).filter(AnalystReview.relationship_id == relationship_id).delete(
        synchronize_session=False
    )
    db.delete(rel)
    db.commit()
    audit(db, user.username, "delete_relationship", f"relationship {relationship_id}")
    return {"ok": True}


def _relationship_graph(db: Session) -> nx.Graph:
    graph = nx.Graph()
    for actor in db.query(Actor).all():
        graph.add_node(f"actor_{actor.id}")
    for rel in db.query(Relationship).all():
        s_type, s_id, t_type, t_id = _relationship_endpoints(rel)
        if not s_id or not t_id:
            continue
        source = f"actor_{s_id}" if s_type == "actor" else f"{s_type}_{s_id}"
        target = f"actor_{t_id}" if t_type == "actor" else f"{t_type}_{t_id}"
        graph.add_edge(source, target, weight=rel.score or 0.0)
    return graph


@router.get("/components")
def connected_components(db: Session = Depends(get_db), user=Depends(get_current_user)):
    graph = _relationship_graph(db)
    components = list(nx.connected_components(graph))
    components.sort(key=len, reverse=True)
    return {
        "component_count": len(components),
        "components": [sorted(component) for component in components],
    }


@router.get("/clusters")
def suspicious_clusters(db: Session = Depends(get_db), user=Depends(get_current_user)):
    graph = _relationship_graph(db)
    if graph.number_of_edges() == 0:
        return {
            "cluster_count": 0,
            "clusters": [],
            "note": "No relationships yet. Build relationships from shared identifiers first.",
        }
    try:
        from networkx.algorithms import community

        communities = community.greedy_modularity_communities(graph, weight="weight")
        clusters = [sorted(group) for group in communities]
    except Exception:
        clusters = [sorted(component) for component in nx.connected_components(graph)]
    return {"cluster_count": len(clusters), "clusters": clusters}
