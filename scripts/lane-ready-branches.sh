#!/usr/bin/env bash
# List remote lane branches that have protocol-v2 closeouts ready for review.
#
# Read-only by design:
# - fetches refs unless --no-fetch is passed
# - creates temporary detached worktrees to run the existing closeout checker
# - never merges, pushes, deletes, rebases, or edits the current checkout

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Per-project glue: coord dir (closeouts live under it).
. "$ROOT/scripts/lib/swarm-config.sh"

LANE="G"
BASE="origin/main"
REMOTE="origin"
FETCH=1
QUEUE_FILE=""
PATTERN=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/lane-ready-branches.sh [options]

Options:
  --lane <letter>       Lane letter to inspect (default: G)
  --base <ref>          Base ref to compare against (default: origin/main)
  --remote <name>       Git remote name (default: origin)
  --pattern <glob>      Remote branch glob (default: sprint/8.1.<lane>.*)
  --queue-file <path>   Write READY branch names, one per line
  --no-fetch            Do not fetch before scanning
  -h, --help            Show this help

Output statuses:
  READY         Unmerged branch has at least one new *DONE.md closeout and all pass protocol-v2 check
  CHECK_FAILED  Closeout exists but protocol-v2 checker failed
  NO_CLOSEOUT   Branch is ahead of base but has no new lane closeout
  MERGED        Remote branch tip is already reachable from base
  LANDED        Tip is NOT reachable, but every commit's content is already in
                base under different shas -- what an isolated-worktree
                cherry-pick leaves behind. Nothing to land; safe to delete.

This script is read-only. It does not merge or delete branches.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lane)
      LANE="${2:?missing --lane value}"
      shift 2
      ;;
    --base)
      BASE="${2:?missing --base value}"
      shift 2
      ;;
    --remote)
      REMOTE="${2:?missing --remote value}"
      shift 2
      ;;
    --pattern)
      PATTERN="${2:?missing --pattern value}"
      shift 2
      ;;
    --queue-file)
      QUEUE_FILE="${2:?missing --queue-file value}"
      shift 2
      ;;
    --no-fetch)
      FETCH=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$PATTERN" ]]; then
  PATTERN="sprint/8.1.${LANE}.*"
fi

branches=()
if [[ "$FETCH" -eq 1 ]]; then
  # Worktrees/clones used by agents sometimes only fetch origin/main. Pull the
  # branch namespace explicitly, quietly, and without tags so the audit output
  # remains a readable queue instead of a fetch transcript.
  git fetch --quiet --no-tags "$REMOTE" \
    "+refs/heads/${PATTERN}:refs/remotes/${REMOTE}/${PATTERN}" \
    "+refs/heads/${BASE#${REMOTE}/}:refs/remotes/${REMOTE}/${BASE#${REMOTE}/}"

  while read -r _sha ref; do
    [[ -z "${ref:-}" ]] && continue
    branch="${ref#refs/heads/}"
    branches+=("$branch")
  done < <(git ls-remote --heads "$REMOTE" "$PATTERN")
else
  while IFS= read -r ref; do
    [[ -z "$ref" ]] && continue
    branches+=("${ref#refs/remotes/${REMOTE}/}")
  done < <(git for-each-ref --format='%(refname)' "refs/remotes/${REMOTE}/${PATTERN}" | sort)
fi

if ! git rev-parse --verify "$BASE" >/dev/null 2>&1; then
  echo "ERROR: base ref not found: $BASE" >&2
  exit 2
fi

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/lane-ready-branches.XXXXXX")"
cleanup() {
  while IFS= read -r wt; do
    [[ -z "$wt" ]] && continue
    git worktree remove --force "$wt" >/dev/null 2>&1 || true
  done < <(find "$TMP_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true)
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

if [[ -n "$QUEUE_FILE" ]]; then
  : > "$QUEUE_FILE"
fi

printf '| Status | Branch | Tip | Closeouts |\n'
printf '|---|---|---:|---|\n'

ready_count=0
failed_count=0
no_closeout_count=0
merged_count=0
landed_count=0
branch_count=0

for branch in "${branches[@]}"; do
  remote_ref="${REMOTE}/${branch}"
  branch_count=$((branch_count + 1))

  tip="$(git rev-parse --short "$remote_ref")"

  if git merge-base --is-ancestor "$remote_ref" "$BASE"; then
    merged_count=$((merged_count + 1))
    printf '| MERGED | `%s` | `%s` | - |\n' "$branch" "$tip"
    continue
  fi

  # Ancestry alone under-reports badly in this repo. The documented landing flow
  # is an isolated-worktree cherry-pick, which gives every landed commit a NEW
  # sha, so a fully-landed branch is never an ancestor of the base and falls
  # through to READY / NO_CLOSEOUT as if it were outstanding work.
  #
  # `git cherry` compares by patch-id instead: a '+' line is a commit whose
  # change is genuinely absent from the base, and no '+' lines at all means the
  # branch's entire content is already there under different shas.
  #
  # Kept as its OWN status rather than folded into MERGED. The two are different
  # facts — one tip is reachable, the other only its content is — and an
  # operator deciding what to delete wants to know which one they are looking at.
  if [[ -z "$(git cherry "$BASE" "$remote_ref" 2>/dev/null | grep '^+' || true)" ]]; then
    landed_count=$((landed_count + 1))
    printf '| LANDED | `%s` | `%s` | content already in base under other shas |\n' "$branch" "$tip"
    continue
  fi

  closeouts=()
  while IFS= read -r closeout; do
    [[ -z "$closeout" ]] && continue
    closeouts+=("$closeout")
  done < <(
    git diff --name-only "$BASE..$remote_ref" -- "${SWARM_COORD_DIR}/inbox/lane-${LANE}/*DONE*.md" \
      | grep -v "${SWARM_COORD_DIR}/inbox/REJECTED/" \
      || true
  )

  if [[ "${#closeouts[@]}" -eq 0 ]]; then
    no_closeout_count=$((no_closeout_count + 1))
    printf '| NO_CLOSEOUT | `%s` | `%s` | - |\n' "$branch" "$tip"
    continue
  fi

  wt="${TMP_ROOT}/${branch//\//__}"
  git worktree add --detach "$wt" "$remote_ref" >/dev/null 2>&1

  checker_ok=1
  checker_log="${TMP_ROOT}/${branch//\//__}.log"
  : > "$checker_log"
  for closeout in "${closeouts[@]}"; do
    if ! (cd "$wt" && bash scripts/protocol-v2-closeout-check.sh "$closeout" >> "$checker_log" 2>&1); then
      checker_ok=0
    fi
  done

  joined="$(printf '`%s`, ' "${closeouts[@]}")"
  joined="${joined%, }"

  if [[ "$checker_ok" -eq 1 ]]; then
    ready_count=$((ready_count + 1))
    printf '| READY | `%s` | `%s` | %s |\n' "$branch" "$tip" "$joined"
    if [[ -n "$QUEUE_FILE" ]]; then
      printf '%s\n' "$branch" >> "$QUEUE_FILE"
    fi
  else
    failed_count=$((failed_count + 1))
    printf '| CHECK_FAILED | `%s` | `%s` | %s |\n' "$branch" "$tip" "$joined"
    sed 's/^/    /' "$checker_log" >&2
  fi
done

printf '\n'
printf 'Summary: branches=%s ready=%s check_failed=%s no_closeout=%s merged=%s landed=%s\n' \
  "$branch_count" "$ready_count" "$failed_count" "$no_closeout_count" "$merged_count" "$landed_count"

if [[ "$failed_count" -gt 0 ]]; then
  exit 1
fi
