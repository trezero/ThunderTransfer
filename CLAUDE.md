# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

ThunderTransfer is a Windows desktop application for high-speed file transfers between two laptops connected via a Thunderbolt USB-C cable. It uses Python + Tkinter. **The entire application lives in a single file: `thunder.py`.**

## Running the App

```bash
pip install -r requirements.txt
python thunder.py
```

No build step, no test suite, no linting config. Development is run-and-test manually.

## Architecture

`thunder.py` (~809 lines) is organized into these layers:

**`TransferStats` (lines 25–42)** — Dataclass tracking total size, bytes sent, speed, ETA, retry count, and a cancellation flag. Shared between the GUI and the send thread.

**`TransferRecord` (lines 44–113)** — Persistence for resumable transfers. Stores progress in `~/.thundertransfer/transfers.json`, keyed by `{target_ip}:{target_dir}:{file_hash}`. Uses SHA-256 of the first+last 1MB for file identity.

**`send_file()` (lines 115–237)** — Client-side transfer logic. Runs in its own thread. Recursively collects files, opens TCP socket to the target, sends a header `"{rel_path}|{size}|{resume_position}|{target_dir}"`, then streams 8KB chunks. MAX_RETRIES=10, RETRY_DELAY=2s.

**`FileTransferServer` (lines 239–329)** — TCP server that runs as a daemon thread. Each accepted connection is handled in its own thread via `handle_client()`, which reads the header, seeks to resume position, and writes chunks to disk.

**`FileTransferApp` (lines 331–751)** — Tkinter GUI. Manages connection settings (local/target IP, port), file/folder selection, destination history (per-IP, LRU-ordered, stored in `~/.thundertransfer/transfer_history.json`), progress bar, speed, and ETA display.

**`get_thunderbolt_ip()` (lines 753–766)** — Detects local 169.254.* IP via `ipconfig` (Windows-only).

**Startup (lines 769–795)** — Checks for Thunderbolt drivers via `driverquery`, prompts user if missing.

## Key Constraints

- **Windows-only**: Uses `ipconfig`, `driverquery`, and Windows path conventions. Do not introduce cross-platform abstractions.
- **No test suite**: Changes must be verified by running the app directly.
- **Single-file monolith**: Keep new logic in `thunder.py` unless explicitly splitting into modules.
- **Threading model**: Server runs in a daemon thread at startup. Each file transfer runs in a non-daemon thread started from the GUI. The `TransferStats.cancelled` flag is the cancellation mechanism — the send thread polls it between chunks.


<!-- archon-rules-start -->
## Archon Knowledge Base — Ambient Behavio

Archon is a RAG knowledge management system connected via MCP (`archon` server). It provides semantic search across project documentation and shared cross-project knowledge. Use the `/archon-memory` skill for explicit operations.

### Session Start — Always Show Status
At the start of every session, check Archon state and display a **one-liner status** to the user:

1. Check if `.claude/archon-state.json` exists in the project
2. If yes, read it and note the Archon `project_id` and `source_id` for searches
3. Check doc freshness: compute MD5 hashes of docs vs stored hashes (use `md5sum <file> | cut -d' ' -f1` on Linux, `md5 -q` on macOS)
4. Display one of these status lines:

   - **Configured & fresh:** `Archon KB: <project> — <N> docs, synced <relative time>, up to date`
   - **Configured & stale:** `Archon KB: <project> — <N> docs, synced <relative time>, <N> files changed. Run /archon-memory sync`
   - **Not configured:** `Archon KB: not configured. Run /archon-memory ingest to set up.`
   - **Server unreachable:** `Archon KB: server unreachable — search unavailable this session`

This check should be quick (read state file + hash a few files). Do NOT call Archon APIs for this — just use local state.

### During Normal Work
- When needing project context (architecture, patterns, deployment, historic issues):
  PREFER `rag_search_knowledge_base(query, project_id)` over reading raw doc files
- Archon search is faster and uses less context than reading entire files
- Fall back to direct file reads only when Archon search returns no relevant results
- For code pattern questions, also try `rag_search_code_examples(query, project_id)`

### When Docs Are Modified
- If documentation files are modified during a session, Archon knowledge is stale
- Remind user to run `/archon-memory sync` before ending the session

### Cross-Project Knowledge
- Shared knowledge (framework docs, tool patterns) is available via `~/.claude/archon-global.json`
- Search shared KB: `rag_search_knowledge_base(query, project_id=shared_project_id)`
<!-- archon-rules-end -->
