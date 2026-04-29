#!/usr/bin/env python3
"""Extract embedded GLSL shaders from ANGLE test files for fuzzer corpus.

Corpus format: [1 byte control] [shader text]
Control byte: bits 0-1 = shader type (0=VS,1=FS,2=CS,3=GS)
              bits 2-3 = spec (0=GLES3.1, 1=GLES3, 2=GLES3.2, 3=GLES2)
              bits 4-6 = output backend index
"""
import os
import re
import hashlib

TEST_DIR = "angle/src/tests/compiler_tests"
CORPUS_DIR = "corpus"

os.makedirs(CORPUS_DIR, exist_ok=True)

shader_pattern = re.compile(
    r'R"\(\s*((?:#version\s+\d+(?:\s+es)?|precision\s+\w+\s+\w+).+?)\)"',
    re.DOTALL
)

quoted_pattern = re.compile(
    r'"((?:#version\s+\d+(?:\\n|[\s\\n])*(?:es)?|precision\s+\w+\s+\w+)[^"]*)"',
    re.DOTALL
)

count = 0

for root, dirs, files in os.walk(TEST_DIR):
    for fname in files:
        if not fname.endswith('.cpp'):
            continue
        fpath = os.path.join(root, fname)
        with open(fpath, 'r', errors='replace') as f:
            content = f.read()

        for m in shader_pattern.finditer(content):
            shader = m.group(1).strip()
            if len(shader) < 20:
                continue

            for output_idx in range(6):
                ctrl = 0x01 | (0x00 << 2) | (output_idx << 4)
                seed = bytes([ctrl]) + shader.encode('utf-8', errors='replace')

                name = hashlib.md5(seed).hexdigest()[:12]
                out_path = os.path.join(CORPUS_DIR, f"shader_{name}")
                with open(out_path, 'wb') as out:
                    out.write(seed)
                count += 1

# Also create some minimal hand-crafted seeds
minimal_shaders = [
    (0x01, "#version 300 es\nprecision mediump float;\nout vec4 fragColor;\nvoid main() { fragColor = vec4(1.0); }"),
    (0x00, "#version 300 es\nin vec4 pos;\nvoid main() { gl_Position = pos; }"),
    (0x02, "#version 310 es\nlayout(local_size_x=1) in;\nvoid main() { }"),
    (0x01, "#version 100\nprecision mediump float;\nvoid main() { gl_FragColor = vec4(1.0, 0.0, 0.0, 1.0); }"),
    (0x00, "#version 100\nattribute vec4 a_position;\nvoid main() { gl_Position = a_position; }"),
    (0x01, "#version 310 es\nprecision highp float;\nout vec4 color;\nuniform sampler2D tex;\nin vec2 uv;\nvoid main() { color = texture(tex, uv); }"),
    (0x00, "#version 300 es\nin vec4 pos;\nuniform mat4 mvp;\nvoid main() { gl_Position = mvp * pos; }"),
    (0x01, "#version 300 es\nprecision mediump float;\nout vec4 c;\nvoid main() {\n  float x = 0.0;\n  for(int i=0; i<10; i++) x += float(i);\n  c = vec4(x);\n}"),
]

for ctrl_base, shader in minimal_shaders:
    for output_idx in range(6):
        ctrl = ctrl_base | (output_idx << 4)
        seed = bytes([ctrl]) + shader.encode('utf-8')
        name = hashlib.md5(seed).hexdigest()[:12]
        out_path = os.path.join(CORPUS_DIR, f"shader_{name}")
        with open(out_path, 'wb') as out:
            out.write(seed)
        count += 1

print(f"Generated {count} seed files in {CORPUS_DIR}/")
