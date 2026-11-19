"""The build must succeed on the template's initial state: an empty sources list.

An empty index keeps the workflow green before any repository is added, so a new
collection does not start with a failing CI run.
"""

import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build_index  # noqa: E402

SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"


class EmptySourcesTest(unittest.TestCase):
    def test_an_empty_sources_file_builds_an_empty_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "sources.txt").write_text("# nothing listed yet\n")
            (root / "collection.json").write_text(json.dumps(
                {"name": "Empty", "indexUrl": "https://example.com/index.json"}))

            saved = (build_index.SOURCES, build_index.COLLECTION, build_index.INDEX,
                     build_index.SIGNATURE, build_index.PUBLIC, build_index.POINTER,
                     os.environ.get("EVILO_SUBSCRIBE_KEY_HEX"))
            build_index.SOURCES = root / "sources.txt"
            build_index.COLLECTION = root / "collection.json"
            build_index.INDEX = root / "index.json"
            build_index.SIGNATURE = root / "index.json.sig"
            build_index.PUBLIC = root / "index.json.pub"
            build_index.POINTER = root / "repo.json"
            os.environ["EVILO_SUBSCRIBE_KEY_HEX"] = SEED
            try:
                self.assertEqual(0, build_index.main())
                index = json.loads((root / "index.json").read_text())
                self.assertEqual([], index["plugins"])
                self.assertEqual(1, index["schemaVersion"])
                pointer = json.loads((root / "repo.json").read_text())
                self.assertEqual(64, len(pointer["signingKeyFingerprint"]))
            finally:
                (build_index.SOURCES, build_index.COLLECTION, build_index.INDEX,
                 build_index.SIGNATURE, build_index.PUBLIC, build_index.POINTER, key) = saved
                if key is None:
                    os.environ.pop("EVILO_SUBSCRIBE_KEY_HEX", None)
                else:
                    os.environ["EVILO_SUBSCRIBE_KEY_HEX"] = key


if __name__ == "__main__":
    unittest.main()
