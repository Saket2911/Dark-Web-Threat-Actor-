from app.database.session import SessionLocal, engine, Base
from app.core.security import hash_password
from app.models.entities import User, Actor, Identifier, Relationship

Base.metadata.create_all(bind=engine)
db = SessionLocal()

# Check all actors
actors = db.query(Actor).all()
print(f"Total actors: {len(actors)}")
print()

# Check identifiers for each actor
for a in actors:
    ids = db.query(Identifier).filter(Identifier.actor_id == a.id).all()
    id_info = [(i.id_type, i.value) for i in ids]
    print(f"Actor {a.id}: {a.primary_handle} ({a.internal_id}) - IDs: {id_info}")

# Check shared identifiers
print("\n=== Checking for shared identifiers ===")
all_ids = {}
for a in actors:
    ids = db.query(Identifier).filter(Identifier.actor_id == a.id).all()
    for i in ids:
        key = f"{i.id_type}:{i.value}"
        if key not in all_ids:
            all_ids[key] = []
        all_ids[key].append(a.id)

shared = {k: v for k, v in all_ids.items() if len(v) > 1}
if shared:
    print(f"\nShared identifiers found: {len(shared)}")
    for key, actor_ids in shared.items():
        actor_names = [db.query(Actor).filter(Actor.id == aid).first().primary_handle for aid in actor_ids]
        print(f"  {key}: actors {[a['primary_handle'] for a in actor_ids]}")
else:
    print("NO shared identifiers found!")

# Check relationships
print(f"\n=== Relationships in DB ===")
rels = db.query(Relationship).all()
print(f"Total relationships: {len(rels)}")
for r in rels:
    print(f"  {r.source_actor_id} -> {r.target_actor_id} ({r.rel_type}, direct={r.direct})")

db.close()