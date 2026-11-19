from fastapi.testclient import TestClient
from app.main import app
from app.database.session import SessionLocal, engine, Base
from app.core.security import hash_password
from app.models.entities import User

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

# Check existing actors
r = client.get("/api/actors", headers=h)
actors = r.json()["items"]
print("Actors:", len(actors))
for a in actors[:10]:
    print(f"  Actor {a['id']}: {a['primary_handle']} (internal: {a['internal_id']})")

# Check graph data
r = client.get("/api/graph/data", headers=h)
data = r.json()
edges = data["edges"]
nodes = data["nodes"]
print()
print(f"Total nodes: {len(nodes)}")
print(f"Total edges: {len(edges)}")

# Count edge types
edge_types = {}
for e in edges:
    label = e["data"]["label"]
    edge_types[label] = edge_types.get(label, 0) + 1
print("Edge types:", edge_types)

# Check shared identifier relationships specifically
shared_edges = [e for e in edges if e["data"]["label"] == "SHARED_IDENTIFIER"]
print(f"SHARED_IDENTIFIER edges: {len(shared_edges)}")
for e in shared_edges[:5]:
    print(f"  {e['data']['source']} -> {e['data']['target']} ({e['data']['label']})")

# Check HAS_IDENTIFIER edges
id_edges = [e for e in edges if e["data"]["label"] == "HAS_IDENTIFIER"]
print(f"HAS_IDENTIFIER edges: {len(id_edges)}")
for e in id_edges[:5]:
    print(f"  {e['data']['source']} -> {e['data']['target']}")