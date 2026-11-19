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