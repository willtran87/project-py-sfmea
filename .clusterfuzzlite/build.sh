#!/bin/bash
set -eu

for fuzzer in "$SRC"/pysfmea/fuzz_targets/*_fuzzer.py; do
  name="$(basename "$fuzzer" .py)"
  package="$name.pkg"
  pyinstaller --distpath "$OUT" --onefile --name "$package" "$fuzzer"
  printf '%s\n' \
    '#!/bin/sh' \
    '# LLVMFuzzerTestOneInput for fuzzer detection.' \
    'this_dir=$(dirname "$0")' \
    'exec "$this_dir/'"$package"'" "$@"' > "$OUT/$name"
  chmod +x "$OUT/$name"
done
