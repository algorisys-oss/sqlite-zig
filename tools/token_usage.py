#!/usr/bin/env python3
"""Report ACTUAL per-prompt token usage for this project's Claude Code session.

Reads the session transcript JSONL (which records real `usage` from the API for
every assistant turn) and aggregates it per user prompt — i.e. the full cost of
a turn: the model's input context, cache creation/read, and generated output,
summed across every assistant step (including all tool-call round-trips) until
the next human prompt. This is the real number, not a chars/4 estimate.

Usage:
    python3 tools/token_usage.py            # human table
    python3 tools/token_usage.py --tsv      # tab-separated (for tokens.txt)

Note: the transcript is session-specific; this reads the newest *.jsonl in the
project's Claude transcript dir. Re-run it at the end of a session to refresh
tokens.txt with that session's real figures.
"""
import glob
import json
import os
import sys
from datetime import datetime, timedelta, timezone

PROJECT_DIR = "/home/rajesh/.claude/projects/-home-rajesh-lab-ai-port-sqlite-zig"
IST = timezone(timedelta(hours=5, minutes=30))


def newest_transcript():
    files = glob.glob(os.path.join(PROJECT_DIR, "*.jsonl"))
    if not files:
        sys.exit(f"no transcript jsonl in {PROJECT_DIR}")
    return max(files, key=os.path.getmtime)


def is_user_text(obj):
    """A real human prompt (not a tool_result echoed back as a user message)."""
    if obj.get("type") != "user":
        return False
    content = obj.get("message", {}).get("content")
    if isinstance(content, str):
        return True
    if isinstance(content, list):
        return any(isinstance(b, dict) and b.get("type") == "text" for b in content)
    return False


def prompt_text(obj):
    content = obj.get("message", {}).get("content")
    if isinstance(content, str):
        return content
    parts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
    return " ".join(parts)


def local(ts):
    if not ts:
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(IST)


def main():
    path = newest_transcript()
    turns = []  # each: dict with summary, start, end, and token sums
    cur = None
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = o.get("type")
        if is_user_text(o):
            cur = {
                "summary": " ".join(prompt_text(o).split())[:80],
                "start": local(o.get("timestamp")),
                "end": local(o.get("timestamp")),
                "input": 0, "cache_creation": 0, "cache_read": 0, "output": 0,
            }
            turns.append(cur)
        elif t == "assistant" and cur is not None:
            u = o.get("message", {}).get("usage", {})
            cur["input"] += u.get("input_tokens", 0)
            cur["cache_creation"] += u.get("cache_creation_input_tokens", 0)
            cur["cache_read"] += u.get("cache_read_input_tokens", 0)
            cur["output"] += u.get("output_tokens", 0)
            end = local(o.get("timestamp"))
            if end:
                cur["end"] = end

    cum = 0
    rows = []
    for i, x in enumerate(turns, 1):
        total = x["input"] + x["cache_creation"] + x["cache_read"] + x["output"]
        cum += total
        rows.append((i, x, total, cum))

    if "--tsv" in sys.argv:
        print("#\tdate\tstart\tend\tinput\tcache_cr\tcache_rd\toutput\ttotal\tcumulative\tsummary")
        for i, x, total, cum in rows:
            d = x["start"].strftime("%Y-%m-%d") if x["start"] else "?"
            s = x["start"].strftime("%H:%M:%S") if x["start"] else "?"
            e = x["end"].strftime("%H:%M:%S") if x["end"] else "?"
            print(f"{i}\t{d}\t{s}\t{e}\t{x['input']}\t{x['cache_creation']}\t{x['cache_read']}\t{x['output']}\t{total}\t{cum}\t{x['summary']}")
        return

    print(f"transcript: {os.path.basename(path)}\n")
    hdr = f"{'#':>2}  {'start':8} {'end':8} {'input':>7} {'cache_cr':>9} {'cache_rd':>9} {'output':>7} {'TOTAL':>9} {'cumul':>10}  prompt"
    print(hdr)
    print("-" * len(hdr))
    for i, x, total, cum in rows:
        s = x["start"].strftime("%H:%M:%S") if x["start"] else "?"
        e = x["end"].strftime("%H:%M:%S") if x["end"] else "?"
        print(f"{i:>2}  {s:8} {e:8} {x['input']:>7} {x['cache_creation']:>9} {x['cache_read']:>9} {x['output']:>7} {total:>9} {cum:>10}  {x['summary']}")
    print(f"\nTotal actual tokens this session: {cum:,}")
    print("(TOTAL per turn = input + cache_creation + cache_read + output, summed over all assistant steps incl. tool round-trips.)")


if __name__ == "__main__":
    main()
