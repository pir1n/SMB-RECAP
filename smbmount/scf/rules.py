"""
SCF rule schema.

Recommended JSON format:

[
  {
    "id": "delete_file_cmd",
    "action": "deletion of file (del)",
    "description": "CREATE -> QUERY_INFO -> SET_INFO FileDispositionInformation",
    "pattern": [
      "<CREATE_SCF>",
      "<QUERY_INFO_SCF>",
      "<SET_INFO_SCF>"
    ],
    "require_success": true
  }
]

Legacy TSV format is still supported by loader.py:

<sequence_hash>\t<action>
"""