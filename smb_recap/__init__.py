"""Public SMB-RECAP namespace.

The implementation remains in :mod:`smbmount` so existing experiment scripts and
archived commands continue to run. Exposing the same package path here provides
the preferred ``smb_recap`` namespace without duplicating implementation modules.
"""

from pathlib import Path

from smbmount import __path__ as _implementation_path

__path__ = [str(Path(__file__).parent), *_implementation_path]
