# Review locally

These optional host captures let you inspect the lab measurements yourself.
Install the [listed prerequisites](../README.md#run-the-checks), run the
commands from the repository root, and use fresh output paths.

```bash
python3 scripts/capture-stack-canary.py host /tmp/canary-review
python3 scripts/export-stack-canary.py /tmp/canary-review \
  --output /tmp/canary-review.json

python3 scripts/capture-return-overwrite.py host /tmp/overwrite-review
python3 scripts/export-return-overwrite.py /tmp/overwrite-review \
  --output /tmp/overwrite-review.json

python3 scripts/capture-pie-leak.py host /tmp/pie-leak-review
python3 scripts/export-pie-leak.py /tmp/pie-leak-review \
  --output /tmp/pie-leak-review.json

python3 scripts/capture-wx.py host /tmp/wx-review
python3 scripts/export-wx.py /tmp/wx-review --output /tmp/wx-review.json

python3 scripts/capture-code-reuse.py host /tmp/code-reuse-review
python3 scripts/export-code-reuse.py /tmp/code-reuse-review \
  --output /tmp/code-reuse-review.json

python3 scripts/capture-relro.py host /tmp/relro-review
python3 scripts/export-relro.py /tmp/relro-review \
  --output /tmp/relro-review.json

python3 scripts/capture-format-string.py host /tmp/format-string-review
python3 scripts/export-format-string.py /tmp/format-string-review \
  --output /tmp/format-string-review.json

python3 scripts/capture-cet.py host /tmp/cet-review
python3 scripts/export-cet.py /tmp/cet-review \
  --output /tmp/cet-review.json

python3 scripts/capture-fortify-coverage.py host /tmp/fortify-review
python3 scripts/export-fortify-coverage.py /tmp/fortify-review \
  --output /tmp/fortify-review.json

python3 scripts/capture-boundary.py host /tmp/boundary-review
python3 scripts/export-boundary.py /tmp/boundary-review \
  --output /tmp/boundary-review.json

# Optional Labs 01–03 host capture and verified text export:
bash scripts/capture-baseline.sh host /tmp/baseline-review
python3 scripts/export-baseline.py /tmp/baseline-review \
  --output /tmp/baseline-review.json
```

The `host` label is a local smoke test. It does not replace the recorded VM
measurements. For VM setup and baseline capture, see [SETUP.md](SETUP.md);
for claims and limitations, see [SYNTHESIS.md](SYNTHESIS.md).
