"""
SCF rule schema.

Recommended JSON format with semantic SCF v2 matching:

[
  {
    "id": "delete_file_cmd",
    "action": "deletion of file (del)",
    "description": "CREATE -> optional noise -> SET_INFO FileDispositionInformation",
    "pattern": [
      {
        "command": "CREATE",
        "features": {"target_type": "file"},
        "contains": {"access_intents": ["delete"]}
      },
      {
        "command": "SET_INFO",
        "features": {
          "file_info_class": "FileDispositionInformation",
          "delete_pending": "1"
        }
      }
    ],
    "max_gap": 4,
    "require_success": true
  }
]

Pattern entries may be:
- a 32-char SCF hash
- a full normalized SCF string
- a command name such as "WRITE"
- an object with command/features/any_features/contains

Legacy TSV format is still supported by loader.py:

<sequence_hash>\t<action>
"""
