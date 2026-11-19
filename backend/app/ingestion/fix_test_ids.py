import re

with open('F:\\Projects\\CN_project\\backend\\tests\\test_api.py', 'r') as f:
    content = f.read()

# Replace all hardcoded actor IDs with uuid.uuid4().hex
content = content.replace('"internal_id": "TA-ghostsec"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-ciphermoth"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-ghostsec2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-TEST1"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-TEST2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-DUP1"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-DUP2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-SYN2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-REAL2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-MAN2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-SYN3"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-REAL3"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-MAN3"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-SYN2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-REAL2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-MAN2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-SYN3"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-REAL3"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": \"TA-MAN3\"', '\"internal_id\": f\"intrusion-set--{uuid.uuid4().hex}\"')
content = content.replace('"internal_id": "TA-SYN3"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-REAL3"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": \"TA-MAN3\"', '\"internal_id\": f\"intrusion-set--{uuid.uuid4().hex}\"')
content = content.replace('"internal_id": "TA-SYN2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-REAL2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')
content = content.replace('"internal_id": "TA-MAN2"', '"internal_id": f"intrusion-set--{uuid.uuid4().hex}"')

with open('F:\\Projects\\CN_project\\backend\\tests\\test_api.py', 'w') as f:
    f.write(content)

print('Fixed all hardcoded actor IDs')