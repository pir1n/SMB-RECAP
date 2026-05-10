import hashlib

from smbmount.scf.normalize import normalize_packet


def fingerprint_packet(pkt):

    text = normalize_packet(pkt)

    return hashlib.md5(
        text.encode()
    ).hexdigest()


def fingerprint_sequence(sequence):

    hashes = []

    for pkt in sequence:
        hashes.append(
            fingerprint_packet(pkt)
        )

    combined = "|".join(hashes)

    return hashlib.md5(
        combined.encode()
    ).hexdigest()