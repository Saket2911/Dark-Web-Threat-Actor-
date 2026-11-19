from fastapi.testclient import TestClient
from app.main import app
from app.database.session import SessionLocal, engine, Base
from app.core.security import hash_password
from app.models.entities import User, Actor, Identifier

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

# Check each actor's identifiers
for a in actors:
    aid = a["id"]
    r = client.get(f"/api/actors/{aid}", headers=h)
    profile = r.json()
    ids = profile.get("identifiers", [])
    id_values = [f"{i['id_type']}:{i['value']}" for i in ids]
    print(f"Actor {a['id']}: {a['primary_handle']} -> identifiers: {id_values}")

# Check for shared identifiers
print("\n=== Checking for shared identifiers ===")
all_idents = {}
for a in actors:
    aid = a["id"]
    r = client.get(f"/api/actors/{aid}", headers=h)
    profile = r.json()
    ids = profile.get("identifiers", [])
    for i in ids:
        key = f"{i['id_type']}:{i['value']}"
        if key not in all_idents:
            all_idents[key] = []
        all_idents[key].append(a["id"])

shared = {k: v for k, v in all_idents.items() if len(v) > 1}
if shared:
    print(f"Shared identifiers found: {len(shared)}")
    for key, actor_ids in shared.items():
        print(f"  {key}: actors {[a['primary_handle'] for a in actors if a['id'] in actor_ids]}")
else:
    print("NO shared identifiers found!")

# Check if any SHARED_IDENTIFIER relationships exist
r = client.get("/api/graph/data", headers=h)
graph_data = r.json()
edges = data["edges"] if (data := r.json()) else []
shared_edges = [e for e in edges if e["data"]["label"] == "SHARED_IDENTIFIER"]
print(f"\nSHARED_IDENTIFIER edges in graph: {len(shared_edges)}")
for e in shared_edges[:5]:
    print(f"  {e['data']['source']} -> {e['data']['target']}")