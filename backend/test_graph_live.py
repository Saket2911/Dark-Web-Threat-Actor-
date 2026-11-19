import requests

base_url = "http://localhost:8000"

# Login
r = requests.post(base_url + "/api/auth/login", json={"username":"tester","password":"testpass"})
print("Login:", r.status_code)
token = r.json()["access_token"]
h = {"Authorization": "Bearer " + token}

# Get actors
r = requests.get(base_url + "/api/actors", headers=h)
print("Actors:", r.status_code, len(r.json()["items"]))
for a in r.json()["items"][:5]:
    print("  Actor", a["id"], a["primary_handle"])

# Build relationships
r = requests.post(base_url + "/api/graph/build", headers=h)
print("Build:", r.status_code, r.json())

# Get graph data
r = requests.get(base_url + "/api/graph/data", headers=h)
print("Graph data:", r.status_code)
if r.status_code == 200:
    data = r.json()
    print("Nodes:", len(data["nodes"]))
    print("Edges:", len(data["edges"]))
    shared_edges = [e for e in data["edges"] if e["data"]["label"] == "SHARED_IDENTIFIER"]
    print("SHARED_IDENTIFIER edges:", len(shared_edges))
    for e in shared_edges[:5]:
        print("  ", e["data"]["source"], "->", e["data"]["target"], "(", e["data"].get("evidence", ""), ")")
else:
    print("Graph error:", r.status_code, r.text[:200])