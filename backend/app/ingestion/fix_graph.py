with open('F:\\Projects\\CN_project\\backend\\app\\ingestion\\mitre_attack.py', 'r') as f:
    content = f.read()

# Add _get_source_type_from_id method at the end of the class
additional_method = '''
    def _get_source_type_from_id(self, stix_id: str) -> str:
        """Determine the entity type from a STIX ID prefix.

        Args:
            stix_id: STIX identifier string.

        Returns:
            The entity type string (actor, campaign, malware, tool, technique, tactic).
        """
        if stix_id.startswith("intrusion-set--"):
            return "actor"
        elif stix_id.startswith("campaign--"):
            return "campaign"
        elif stix_id.startswith("malware--"):
            return "malware"
        elif stix_id.startswith("tool--"):
            return "tool"
        elif stix_id.startswith("x-mitre-tactic--"):
            return "tactic"
        elif stix_id.startswith("attack-pattern--"):
            return "technique"
        elif stix_id.startswith("relationship--"):
            return "relationship"
        return "actor"
'''

content += additional_method

with open('F:\\Projects\\CN_project\\backend\\app\\ingestion\\mitre_attack.py', 'w') as f:
    f.write(content)

print('Added _get_source_type_from_id method at end of file')
print('Checking if _get_source_type_from_id is now in class...')

# Verify
with open('F:\\Projects\\CN_project\\backend\\app\\ingestion\\mitre_attack.py', 'r') as f:
    content = f.read()
    print(f'_get_source_type_from_id appears {content.count("def _get_source_type_from_id")} times in file')