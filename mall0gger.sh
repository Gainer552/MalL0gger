#!/usr/bin/env bash
# Static, read-only analyzer for a single file.
# Prompts user for file path, analyzes it safely, logs all output to a timestamped report,
# and attempts to make the report immutable (via chattr or chmod fallback).

set -o errexit
set -o pipefail
set -o nounset

echo "=============================================="
echo "   Malware Static Analyzer - Interactive Mode"
echo "=============================================="
echo
read -rp "Enter the full path to the file you want to analyze: " SAMPLE

if [[ -z "$SAMPLE" ]]; then
  echo "[!] No input provided. Exiting."
  exit 2
fi

if [[ ! -e "$SAMPLE" ]]; then
  echo "[!] File not found: $SAMPLE"
  exit 3
fi

# Resolve absolute path
SAMPLE="$(readlink -f -- "$SAMPLE" || realpath -- "$SAMPLE" 2>/dev/null || echo "$SAMPLE")"
BNAME="$(basename -- "$SAMPLE")"
TIMESTAMP="$(date -u +"%Y%m%d_%H%M%SZ")"
OUTFILE="analysis_${BNAME}_${TIMESTAMP}.txt"
TMPDIR="$(mktemp -d /tmp/malware_analyze.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

# Limits for output sections
MAX_STRINGS_LINES=5000
MAX_HEXDUMP_BYTES=512
MAX_FILE_PREVIEW_BYTES=4096

# Helper function for timestamped section headers
stamp() { echo "==== $1 ($(date -u +"%Y-%m-%d %H:%M:%SZ")) ===="; }

# Tool availability map
declare -A HAVE
check_tool() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then HAVE["$name"]=1; else HAVE["$name"]=0; fi
}
TOOLS=(file sha1sum sha256sum md5sum sha512sum ssdeep strings xxd hexdump od python3 readelf objdump exiftool yara binwalk upx rizin radare2)
for t in "${TOOLS[@]}"; do check_tool "$t"; done

append_section() {
  local title="$1"
  {
    echo
    echo "################################################################"
    echo "$(stamp "$title")"
    echo
  } >> "$OUTFILE"
}

# ---- BEGIN ANALYSIS ----
{
  echo "Malware Static Analysis Report"
  echo "Sample: $SAMPLE"
  echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%SZ") (UTC)"
  echo "Host: $(hostname -f 2>/dev/null || hostname)"
  echo "User: $(id -un) UID=$(id -u) GID=$(id -g)"
  echo "Script: $(readlink -f -- "$0" || echo "$0")"
  echo
} > "$OUTFILE"

#####################
# 1) Basic metadata #
#####################
append_section "Basic file metadata"
{
  echo "Path: $SAMPLE"
  echo "Basename: $BNAME"
  echo "Size (bytes): $(stat -c%s -- "$SAMPLE" 2>/dev/null || stat -f%z -- "$SAMPLE" 2>/dev/null || echo 'N/A')"
  echo "Last modified: $(stat -c%y -- "$SAMPLE" 2>/dev/null || stat -f"%Sm" -- "$SAMPLE" 2>/dev/null || echo 'N/A')"
  echo "Permissions: $(stat -c%A -- "$SAMPLE" 2>/dev/null || stat -f"%Lp" -- "$SAMPLE" 2>/dev/null || echo 'N/A')"
  echo "Owner: $(stat -c%U:%G -- "$SAMPLE" 2>/dev/null || echo 'N/A')"
  if [[ "${HAVE[file]:-0}" -eq 1 ]]; then
    echo "file(1) output: $(file -b --mime-type "$SAMPLE") — $(file -b --mime-encoding "$SAMPLE" 2>/dev/null || true)"
    echo "file(1) long: $(file -b "$SAMPLE")"
  else
    echo "file(1) not available"
  fi
} >> "$OUTFILE"

#################
# 2) Hashes     #
#################
append_section "Hashes (MD5 / SHA1 / SHA256 / SHA512 / ssdeep)"
{
  [[ "${HAVE[md5sum]:-0}" -eq 1 ]] && md5sum "$SAMPLE" || echo "md5sum not available"
  [[ "${HAVE[sha1sum]:-0}" -eq 1 ]] && sha1sum "$SAMPLE" || echo "sha1sum not available"
  [[ "${HAVE[sha256sum]:-0}" -eq 1 ]] && sha256sum "$SAMPLE" || echo "sha256sum not available"
  [[ "${HAVE[sha512sum]:-0}" -eq 1 ]] && sha512sum "$SAMPLE" || echo "sha512sum not available"
  if [[ "${HAVE[ssdeep]:-0}" -eq 1 ]]; then
    echo "ssdeep (fuzzy hash):"
    ssdeep -b "$SAMPLE" 2>/dev/null || true
  fi
} >> "$OUTFILE"

#################
# 3) Entropy    #
#################
append_section "Entropy (Shannon)"
{
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$SAMPLE" <<'PY'
import sys,math
from collections import Counter
p=sys.argv[1]
try: b=open(p,'rb').read()
except Exception as e: print("Could not read:",e); sys.exit(0)
if not b: print("Empty file"); sys.exit(0)
c=Counter(b); l=len(b)
h=-sum((v/l)*math.log2((v/l)) for v in c.values())
print("Size bytes:", l)
print("Entropy bits/byte:", round(h,6))
PY
  else
    echo "python3 not available — entropy skipped"
  fi
} >> "$OUTFILE"

#################
# 4) Header hex #
#################
append_section "Header hex (first ${MAX_HEXDUMP_BYTES} bytes)"
{
  if command -v xxd >/dev/null 2>&1; then
    xxd -g 1 -l "$MAX_HEXDUMP_BYTES" "$SAMPLE" 2>/dev/null || hexdump -C -n "$MAX_HEXDUMP_BYTES" "$SAMPLE"
  else
    hexdump -C -n "$MAX_HEXDUMP_BYTES" "$SAMPLE"
  fi
} >> "$OUTFILE"

########################
# 5) Strings & IOCs    #
########################
append_section "Strings and potential network indicators"
{
  if [[ "${HAVE[strings]:-0}" -eq 1 ]]; then
    strings -a -n 4 "$SAMPLE" | sed -n "1,${MAX_STRINGS_LINES}p" > "$TMPDIR/strings.txt"
    echo "Strings file saved to: $TMPDIR/strings.txt"
    sed -n "1,${MAX_STRINGS_LINES}p" "$TMPDIR/strings.txt"
  fi
  echo
  echo "---- Network indicators ----"
  if [[ -f "$TMPDIR/strings.txt" ]]; then
    grep -Eo '(https?://[^"[:space:]]+)' "$TMPDIR/strings.txt" | sort -u | sed -n '1,100p'
    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$TMPDIR/strings.txt" | sort -u | sed -n '1,100p'
    grep -Eo '([a-z0-9\-]+\.)+[a-z]{2,}' "$TMPDIR/strings.txt" | sort -u | sed -n '1,100p'
  fi
} >> "$OUTFILE"

########################
# 6) Archive checks    #
########################
append_section "Archive / container detection"
{
  MIMETYPE="$(file -b --mime-type "$SAMPLE" 2>/dev/null || true)"
  echo "Mime-type: $MIMETYPE"
  if command -v zipinfo >/dev/null && echo "$MIMETYPE" | grep -q 'zip'; then
    zipinfo -1 "$SAMPLE" | sed -n '1,100p'
  fi
  if command -v tar >/dev/null && echo "$MIMETYPE" | grep -q 'tar'; then
    tar -tvf "$SAMPLE" | sed -n '1,100p'
  fi
  if command -v binwalk >/dev/null; then
    binwalk -m "$SAMPLE" | sed -n '1,100p'
  fi
} >> "$OUTFILE"

########################
# 7) Binary specifics  #
########################
append_section "Binary-specific info (ELF/PE)"
{
  FILEINFO="$(file -b "$SAMPLE")"
  echo "file(1): $FILEINFO"
  if echo "$FILEINFO" | grep -qi 'ELF'; then
    [[ "${HAVE[readelf]}" -eq 1 ]] && readelf -h "$SAMPLE" | sed -n '1,200p'
  elif echo "$FILEINFO" | grep -qi 'PE32'; then
    [[ "${HAVE[objdump]}" -eq 1 ]] && objdump -p "$SAMPLE" | sed -n '1,200p'
  fi
} >> "$OUTFILE"

########################
# 8) YARA signatures   #
########################
append_section "YARA signatures (if available)"
{
  if command -v yara >/dev/null; then
    DEFAULT_YARA_DIRS="/usr/local/etc/yara:/etc/yara:/usr/share/yara"
    FOUND_RULES=""
    for d in $(echo "$DEFAULT_YARA_DIRS" | tr ':' ' '); do
      [[ -d "$d" ]] && FOUND_RULES+=" $(find "$d" -type f -iname '*.yar*' 2>/dev/null)"
    done
    if [[ -n "$FOUND_RULES" ]]; then
      yara -r $(echo "$FOUND_RULES" | tr ' ' '\n' | head -n 10) "$SAMPLE" | head -n 100
    else
      echo "No YARA rules found."
    fi
  else
    echo "YARA not installed."
  fi
} >> "$OUTFILE"

########################
# 9) Certificates      #
########################
append_section "Certificates / crypto artifacts"
{
  if command -v openssl >/dev/null; then
    grep -n 'BEGIN CERTIFICATE' "$TMPDIR/strings.txt" || true
  else
    echo "openssl not found."
  fi
} >> "$OUTFILE"

########################
# 10) Safe preview     #
########################
append_section "Safe preview of first ${MAX_FILE_PREVIEW_BYTES} bytes"
{
  dd if="$SAMPLE" bs=1 count="$MAX_FILE_PREVIEW_BYTES" status=none | sed -n '1,200p'
} >> "$OUTFILE"

########################
# 11) Analyst notes    #
########################
append_section "Analyst notes & next steps"
{
  echo "- High entropy suggests possible packing or encryption."
  echo "- URLs or IPs found: handle in isolated sandbox or passive DNS lookup."
  echo "- Consider submitting hashes to threat intel sources (VirusTotal, MISP)."
  echo "- All actions are static (read-only)."
} >> "$OUTFILE"

########################
# 12) Make immutable   #
########################
append_section "Finalization: make report immutable"
{
  echo "Report path: $(readlink -f "$OUTFILE")"
  if command -v chattr >/dev/null 2>&1; then
    if chattr +i "$OUTFILE" 2>/dev/null; then
      echo "Applied chattr +i (immutable)."
    else
      chmod 400 "$OUTFILE" 2>/dev/null && echo "Fallback: chmod 400 (read-only)."
    fi
  else
    chmod 400 "$OUTFILE" 2>/dev/null && echo "Applied chmod 400 (read-only)."
  fi
  ls -l "$OUTFILE"
} >> "$OUTFILE"

# ---- COMPLETE ----
echo
echo "Analysis complete!"
echo "Report saved as: $OUTFILE"
echo "Immutable flag applied (or chmod fallback)."
echo
