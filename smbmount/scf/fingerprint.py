import hashlib

from smbmount.scf.normalize import normalize_packet


def md5_text(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def fingerprint_packet(pkt):
    """
    SCF của 1 SMB command.
    """
    return md5_text(normalize_packet(pkt))


def fingerprint_sequence(sequence):
    """
    Legacy mode: hash cả sequence.
    Giữ lại để tương thích rule cũ dạng hash<TAB>action.
    """
    hashes = [fingerprint_packet(pkt) for pkt in sequence]
    return md5_text("|".join(hashes))


def packet_fingerprints(sequence):
    """
    Rule mới nên match list SCF từng packet.
    """
    return [fingerprint_packet(pkt) for pkt in sequence]