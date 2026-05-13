#!/usr/bin/env bash
set -euo pipefail
mkdir -p data/raw
if [ -f /mnt/data/sec_vul_eval-train.arrow ]; then
  cp /mnt/data/sec_vul_eval-train.arrow data/raw/sec_vul_eval-train.arrow
  echo "Copied /mnt/data/sec_vul_eval-train.arrow -> data/raw/sec_vul_eval-train.arrow"
else
  echo "Upload/copy sec_vul_eval-train.arrow into data/raw/ manually."
fi
