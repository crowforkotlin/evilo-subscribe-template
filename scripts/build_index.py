#!/usr/bin/env python3
"""Fetch every listed plugin repository and build a signed subscription index.

Inputs:
    sources.txt           One plugin catalog URL per line; '#' starts a comment.
    collection.json       The collection name and its public identity.
    EVILO_SUBSCRIBE_KEY_HEX   64-hex Ed25519 seed, read from the environment.

Outputs (written next to sources.txt):
    index.json            Merged plugin records, the exact bytes that get signed.
    index.sig             Ed25519 signature over index.json, lowercase hex.
    repo.json             The pointer consumers subscribe to.

The index is rebuilt from scratch on every run. It never accumulates state, so a
plugin repository that removes a release or changes a description is reflected
on the next build without any manual editing here.
"""

import hashlib
import json
import os
import pathlib
import ssl
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = ROOT / "sources.txt"
COLLECTION = ROOT / "collection.json"
INDEX = ROOT / "index.json"
SIGNATURE = ROOT / "index.json.sig"
PUBLIC = ROOT / "index.json.pub"
POINTER = ROOT / "repo.json"

SCHEMA_VERSION = 1
FETCH_TIMEOUT = 30
MAX_BYTES = 10 * 1024 * 1024


def fail(message):
    raise SystemExit(f"build_index: {message}")


def read_sources():
    if not SOURCES.exists():
        fail(f"missing {SOURCES}")
    entries = []
    for number, raw in enumerate(SOURCES.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if not line.startswith(("https://", "http://")):
            fail(f"sources.txt line {number} is not an absolute HTTP(S) URL: {line}")
        if line in entries:
            fail(f"sources.txt line {number} repeats an earlier entry: {line}")
        entries.append(line)
    if not entries:
        fail("sources.txt lists no plugin repositories")
    return entries


def fetch_json(url):
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "evilo-subscribe"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
            if response.status != 200:
                fail(f"{url} returned HTTP {response.status}")
            payload = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as error:
        fail(f"{url} returned HTTP {error.code}")
    except (urllib.error.URLError, ssl.SSLError, TimeoutError) as error:
        fail(f"{url} is unreachable: {error}")
    if len(payload) > MAX_BYTES:
        fail(f"{url} exceeds {MAX_BYTES} bytes")
    try:
        return json.loads(payload)
    except json.JSONDecodeError as error:
        fail(f"{url} is not JSON: {error}")


def plugin_record(url, plugin):
    """Reduce one catalog plugin to what a list row needs, plus where to fetch more."""
    versions = plugin.get("availableVersions") or []
    if not versions:
        fail(f"{url} plugin {plugin.get('id')} lists no versions")
    latest = max(versions, key=lambda release: int(release.get("versionCode", 0)))
    authors = []
    for author in plugin.get("authors") or []:
        authors.append(author if isinstance(author, str) else author.get("name", ""))
    return {
        "catalogUrl": url,
        "publishedAt": latest.get("publishedAt", ""),
        "id": plugin.get("id", ""),
        "name": plugin.get("name", ""),
        "version": latest.get("version", ""),
        "versionCode": int(latest.get("versionCode", 0)),
        "iconUrl": plugin.get("iconUrl", ""),
        "authors": [name for name in authors if name],
        "description": plugin.get("description", ""),
    }


def build_index(sources):
    records = []
    seen = {}
    for url in sources:
        document = fetch_json(url)
        plugins = document.get("plugins")
        if not isinstance(plugins, list):
            fail(f"{url} is not a plugin catalog: it declares no plugins list")
        for plugin in plugins:
            record = plugin_record(url, plugin)
            if not record["id"]:
                fail(f"{url} contains a plugin without an id")
            previous = seen.get(record["id"])
            if previous is not None:
                fail(f"plugin id {record['id']} appears in both {previous} and {url}; an id must have one publisher")
            seen[record["id"]] = url
            records.append(record)
    records.sort(key=lambda record: record["id"])
    updated_at = os.environ.get("EVILO_SUBSCRIBE_UPDATED_AT") or newest_publication(records)
    for record in records:
        record.pop("publishedAt", None)
    collection = json.loads(COLLECTION.read_text(encoding="utf-8"))
    return {
        "schemaVersion": SCHEMA_VERSION,
        "name": collection["name"],
        "updatedAt": updated_at,
        "plugins": records,
    }


def newest_publication(records):
    """The newest release date seen, so the field reflects the source data, not the clock."""
    dates = [record["publishedAt"] for record in records if record.get("publishedAt")]
    if not dates:
        return "1970-01-01T00:00:00Z"
    newest = max(dates)
    return newest if "T" in newest else f"{newest}T00:00:00Z"


def main():
    key_hex = os.environ.get("EVILO_SUBSCRIBE_KEY_HEX", "").strip()
    if key_hex and not (len(key_hex) == 64 and all(character in "0123456789abcdef" for character in key_hex.lower())):
        fail("EVILO_SUBSCRIBE_KEY_HEX must be 64 hexadecimal characters")

    sources = read_sources()
    index = build_index(sources)
    body = (json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    INDEX.write_bytes(body)

    if not key_hex:
        print("build_index: no signing key supplied; wrote index.json without a signature")
        return 0

    signature = sign(body, bytes.fromhex(key_hex))
    public_key = public_from_seed(bytes.fromhex(key_hex))
    SIGNATURE.write_text(signature.hex() + "\n", encoding="ascii")
    PUBLIC.write_text(public_key.hex() + "\n", encoding="ascii")

    collection = json.loads(COLLECTION.read_text(encoding="utf-8"))
    pointer = {
        "name": collection["name"],
        "indexUrl": collection["indexUrl"],
        "signingKeyFingerprint": hashlib.sha256(public_key).hexdigest(),
        "keyId": collection.get("keyId", "subscription"),
    }
    POINTER.write_text(json.dumps(pointer, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"build_index: {len(index['plugins'])} plugins from {len(sources)} repositories")
    print(f"build_index: fingerprint {pointer['signingKeyFingerprint']}")
    return 0


def public_from_seed(seed):
    """Derive the Ed25519 public key from its 32-byte seed, per RFC 8032 section 5.1.5."""
    if len(seed) != 32:
        fail("the signing seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return point_encode(scalar_mult_base(bytes(scalar)))


def sign(message, seed):
    digest = hashlib.sha512(seed).digest()
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    prefix = digest[32:]
    public_key = point_encode(scalar_mult_base(bytes(scalar)))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % GROUP_ORDER
    r_encoded = point_encode(scalar_mult_base(r.to_bytes(32, "little")))
    h = int.from_bytes(hashlib.sha512(r_encoded + public_key + message).digest(), "little") % GROUP_ORDER
    s = (r + h * int.from_bytes(scalar, "little")) % GROUP_ORDER
    return r_encoded + s.to_bytes(32, "little")


# The Edwards25519 arithmetic below is the minimum needed to derive a public key and
# sign. It is not a general-purpose curve library.

P = 2 ** 255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
GROUP_ORDER = 2 ** 252 + 27742317777372353535851937790883648493


def point_add(a, b):
    x1, y1 = a
    x2, y2 = b
    denominator = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + denominator, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - denominator, P - 2, P) % P
    return x3, y3


def point_mul(point, scalar):
    result = (0, 1)
    while scalar:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return result


def recover_x(y):
    value = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(value, (P + 3) // 8, P)
    if (x * x - value) % P != 0:
        x = x * pow(2, (P - 1) // 4, P) % P
    if x % 2:
        x = P - x
    return x


BASE_Y = 4 * pow(5, P - 2, P) % P
BASE = (recover_x(BASE_Y), BASE_Y)


def scalar_mult_base(scalar):
    return point_mul(BASE, int.from_bytes(scalar, "little"))


def point_encode(point):
    x, y = point
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


if __name__ == "__main__":
    sys.exit(main())
