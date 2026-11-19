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
print("Login:", r.status_code, r.json())
token = r.json()["access_token"]
h = {"Authorization": f"Bearer {token}"}

r = client.get("/api/actors", headers=h)
data = r.json()
print("Actors:", r.status_code, len(data["items"]))

r = client.post("/api/graph/build", headers=h)
print("Build:", r.status_code, r.json())

r = client.get("/api/graph/data", headers=h)
print("Graph data:", r.status_code)
if r.status_code == 200:
    data = r.json()
    print("Nodes:", len(data["nodes"]))
    print("Edges:", len(data["edges"]))
    for e in data["edges"][:5]:
        print("  Edge:", e["data"])
