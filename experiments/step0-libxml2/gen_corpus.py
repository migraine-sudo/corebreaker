#!/usr/bin/env python3
"""Generate fuzzer corpus from libxml2 Relax-NG test files.

Seed format: [2-byte big-endian split][schema bytes][document bytes]
Harness logic: schema_len = split % (payload_size + 1)
So we set split = schema_len directly (works when schema_len < 65536).
"""
import os
import struct
import hashlib

TEST_DIR = "libxml2-src/test/relaxng"
CORPUS_DIR = "corpus"

os.makedirs(CORPUS_DIR, exist_ok=True)

# Clean old seeds
for f in os.listdir(CORPUS_DIR):
    os.remove(os.path.join(CORPUS_DIR, f))

rng_files = sorted(f for f in os.listdir(TEST_DIR) if f.endswith('.rng'))
xml_files = sorted(f for f in os.listdir(TEST_DIR) if f.endswith('.xml'))

count = 0

for rng in rng_files:
    rng_path = os.path.join(TEST_DIR, rng)
    base = rng.replace('.rng', '')

    with open(rng_path, 'rb') as f:
        schema_data = f.read()

    # Skip very large schemas to keep seeds reasonable
    if len(schema_data) > 4000:
        schema_data = schema_data[:4000]

    matched_xmls = [x for x in xml_files if x.startswith(base + '_')]

    if not matched_xmls:
        matched_xmls = [None]

    for xml_name in matched_xmls:
        if xml_name is None:
            doc_data = b'<?xml version="1.0"?>\n<root/>'
        else:
            xml_path = os.path.join(TEST_DIR, xml_name)
            with open(xml_path, 'rb') as f:
                doc_data = f.read()
            if len(doc_data) > 4000:
                doc_data = doc_data[:4000]

        schema_len = len(schema_data)
        payload = schema_data + doc_data
        payload_size = len(payload)

        # We need: split % (payload_size + 1) == schema_len
        # Since schema_len < payload_size + 1, just use split = schema_len
        if schema_len > 65535:
            continue

        split_bytes = struct.pack('>H', schema_len)
        seed = split_bytes + payload

        # Verify
        check_split = struct.unpack('>H', seed[:2])[0]
        check_schema_len = check_split % (payload_size + 1)
        assert check_schema_len == schema_len, f"Split mismatch: {check_schema_len} != {schema_len}"

        name = hashlib.md5(seed).hexdigest()[:12]
        out_path = os.path.join(CORPUS_DIR, f"seed_{name}")

        with open(out_path, 'wb') as f:
            f.write(seed)
        count += 1

print(f"Generated {count} seed files in {CORPUS_DIR}/")
