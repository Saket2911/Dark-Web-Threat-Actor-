with open('F:/Projects/CN_project/backend/app/ingestion/mitre_attack.py', 'r') as f:
    content = f.read()
print('Has _get_source_type_from_id:', '_get_source_type_from_id' in content)
print('Total length:', len(content))