import hashlib

from smbmount.scf.normalize import normalize_packet, packet_features


def md5_text(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def fingerprint_packet(pkt):
    """
    Stable SCF hash của 1 SMB command.
    """
    return md5_text(normalize_packet(pkt))


def signature_packet(pkt):
    normalized = normalize_packet(pkt)
    return {
        "scf": md5_text(normalized),
        "normalized": normalized,
        "features": packet_features(pkt),
    }


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


def packet_signatures(sequence):
    return [signature_packet(pkt) for pkt in sequence]
