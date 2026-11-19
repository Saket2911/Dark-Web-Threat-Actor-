from fastapi.testclient import TestClient
from app.main import app
from app.database.session import SessionLocal, engine, Base
from app.core.security import hash_password
from app.models.entities import User, Actor, Identifier, Relationship

Base.metadata.create_all(bind=engine)
db = SessionLocal()
if not db.query(User).filter(User.username=="tester").first():
    db.add(User(username="tester", hashed_password=hash_password("testpass"), role="analyst"))
    db.commit()
db.close()

client = TestClient(app)
r = client.post("/api/auth/login", json={"username":"tester","password":"testpass"})
token = r.json()["access_token"]
h = {"Authorization": "Bearer " + token}

# Get all actors with their identifiers
r = client.get("/api/actors", headers=h)
actors = r.json()["items"]
print(f"Total actors: {len(actors)}")
print()

all_ids = {}
for a in actors:
    aid = a["id"]
    r = client.get(f"/api/actors/{aid}", headers=h)
    profile = r.json()
    ids = profile.get("identifiers", [])
    id_values = [(i["id_type"], i["value"]) for i in ids]
    print(f"Actor {a['id']}: {a['primary_handle']} -> {id_values}")
    for i in ids:
        key = f"{i['id_type']}:{i['value']}"
        if key not in all_ids:
            all_ids[key] = []
        all_ids[key].append(a["id"])

print("\n=== Shared identifiers ===")
shared = {k: v for k, v in all_ids.items() if len(v) > 1}
if shared:
    for key, actor_ids in shared.items():
        actor_names = [db.query(Actor).filter(Actor.id == aid).first().primary_handle for aid in actor_ids]
        print(f"  {key}: actors {[a['primary_handle'] for a in actor_ids]}")
else:
    print("No shared identifiers found!")

# Check relationships
r = client.get("/api/graph/data", headers=h)
graph_data = r.json()
edges = graph_data.get("edges", [])
shared_edges = [e for e in edges if e["data"]["label"] == "SHARED_IDENTIFIER"]
print(f"\nSHARED_IDENTIFIER edges in graph: {len(shared_edges)}")
for e in shared_edges[:5]:
    print(f"  {e['data']['source']} -> {e['data']['target']}")