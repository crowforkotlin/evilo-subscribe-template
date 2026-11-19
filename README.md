# evilo-subscribe-template

A subscription collection for evilo: one address that brings in many plugin repositories.

## What you maintain

`collection.json` holds the name and where the index will be served:

```json
{
  "name": "Awesome evilo plugins",
  "indexUrl": "https://raw.githubusercontent.com/OWNER/REPO/main/index.json",
  "keyId": "subscription"
}
```

`sources.txt` holds one plugin repository URL per line; `#` starts a comment:

```text
https://raw.githubusercontent.com/alice/alice-plugin/main/catalog.json
https://raw.githubusercontent.com/bob/bob-plugin/main/catalog.json
```

Those two files are the whole input. Everything else is generated.

## What the build produces

| File | Contents |
| --- | --- |
| `index.json` | Every plugin of every listed repository: `id`, `name`, `version`, `versionCode`, `iconUrl`, `authors`, `description`, `catalogUrl` |
| `index.json.sig` | Ed25519 signature over the exact `index.json` bytes, lowercase hex |
| `index.json.pub` | The signing public key, so a subscriber can re-derive the fingerprint |
| `repo.json` | The pointer users subscribe to: `indexUrl`, `signingKeyFingerprint`, `keyId` |

The index is rebuilt from scratch each run. A repository that publishes a new version,
changes its description, or removes a release appears correctly after the next build;
nothing here restates its metadata.

## Why the index exists

A collection of URLs alone costs one HTTP request per repository. One thousand
repositories would mean one thousand requests before the user sees anything.

With an index, the user's app makes two requests: `repo.json`, then `index.json`.
The index is one document, measured at about 620 bytes per plugin, so ten thousand
plugins fit in the 10 MiB the app accepts.

## Signing

The index is signed so a compromised host cannot inject plugins.

1. Generate one Ed25519 seed and keep it private:

   ```sh
   python3 - <<'PY'
   import secrets
   print(secrets.token_hex(32))
   PY
   ```

2. Store it as the repository secret `EVILO_SUBSCRIBE_KEY_HEX`.

3. The first build writes `signingKeyFingerprint` into `repo.json`. That value is the
   SHA-256 of the raw public key.

A subscriber who sees a different fingerprint is looking at a different publisher.
The app rejects an index whose key does not match the subscribed fingerprint, so
replacing the key requires the user to subscribe again.

`EVILO_SUBSCRIBE_KEY_HEX` must be different from a plugin publishing key: this one
signs an index, plugin keys sign plugin manifests.

## Build locally

```sh
python3 - <<'PY'
import pathlib, sys
sys.path.insert(0, "scripts")
import build_index as build
seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
assert build.public_from_seed(seed).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
assert build.sign(b"", seed).hex() == (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
print("ok")
PY

EVILO_SUBSCRIBE_KEY_HEX=<your 64-hex seed> python3 scripts/build_index.py
```

Without the key the build still writes `index.json` but no signature or `repo.json`,
which is useful for inspecting the merged result.

## Subscribe

Point the app at:

```text
https://raw.githubusercontent.com/OWNER/REPO/main/repo.json
```

The app fetches that pointer, verifies the fingerprint, fetches the index, and verifies
the signature before listing any plugin.

## Limitations

The build fails rather than guessing: an unreachable repository, a non-JSON response,
a missing `plugins` list, or one plugin id claimed by two repositories stops the whole
build. A broken source is visible immediately instead of silently disappearing from the
index.
