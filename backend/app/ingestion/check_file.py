with open('F:\\Projects\\CN_project\\backend\\app\\ingestion\\mitre_attack.py', 'r') as f:
    content = f.read()

print(f'Total lines: {len(content.splitlines())}')
print(f'Has _get_source_type_from_id: {"_get_source_type_from_id" in content}')
print(f'Has _parse_iso_datetime: {"_parse_iso_datetime" in content}')
print(f'Count of _get_source_type_from_id def: {content.count("def _get_source_type_from_id")}')
