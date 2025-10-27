"""
Process Tree Plugin for LogSnoop
Parses a JSON array of process events with fields like:
timestamp, process_name, process_id, parent_process_id, image, command_line, md5
"""

from typing import Dict, List, Any
from collections import Counter, defaultdict
from datetime import datetime
import json

from .base import BaseLogPlugin


class ProcessTreePlugin(BaseLogPlugin):
    @property
    def name(self) -> str:
        return "process_tree"

    @property
    def description(self) -> str:
        return "Parse JSON process tree/events (process name, PID, PPID, image, command line, hash)"

    @property
    def supported_queries(self) -> List[str]:
        return [
            "process_list",
            "count_by_name",
            "children_of",
            "tree_from_pid",
            "top_parents",
            "commandline_search",
            "suspicious_spawns",
        ]

    def parse(self, log_content: str) -> Dict[str, Any]:
        try:
            data = json.loads(log_content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

        if not isinstance(data, list):
            raise ValueError("Expected a JSON array of process events")

        entries: List[Dict[str, Any]] = []
        name_counter = Counter()
        parent_counter = Counter()
        md5_set = set()

        start_time = None
        end_time = None

        for i, rec in enumerate(data, start=1):
            ts_raw = str(rec.get("timestamp", ""))
            # Normalize timestamp if possible
            ts_iso = ts_raw
            try:
                # Try common format "YYYY-MM-DD HH:MM:SS"
                ts_iso = datetime.strptime(ts_raw, "%Y-%m-%d %H:%M:%S").isoformat()
            except Exception:
                if ts_raw:
                    # Fallback: try parsing with fromisoformat
                    try:
                        ts_iso = datetime.fromisoformat(ts_raw).isoformat()
                    except Exception:
                        ts_iso = ts_raw

            entry = {
                "line_number": i,
                "timestamp": ts_iso,
                # Table/CLI compatibility fields
                "source_ip": rec.get("process_name", ""),
                "destination_ip": str(rec.get("process_id", "")),
                "bytes_transferred": 0,
                "event_type": "process_event",
                "status": "",
                # Process fields
                "process_name": rec.get("process_name", ""),
                "process_id": rec.get("process_id", 0),
                "parent_process_id": rec.get("parent_process_id", 0),
                "image": rec.get("image", ""),
                "command_line": rec.get("command_line", ""),
                "md5": rec.get("md5", ""),
                # Raw
                "raw_line": json.dumps(rec, ensure_ascii=False),
            }

            entries.append(entry)
            name_counter[entry["process_name"]] += 1
            parent_counter[entry["parent_process_id"]] += 1
            if entry["md5"]:
                md5_set.add(entry["md5"])

            # capture time bounds
            if ts_iso:
                if start_time is None or ts_iso < start_time:
                    start_time = ts_iso
                if end_time is None or ts_iso > end_time:
                    end_time = ts_iso

        summary = {
            "total_entries": len(entries),
            "unique_process_names": len(name_counter),
            "unique_md5": len(md5_set),
            "top_process_names": dict(name_counter.most_common(10)),
            "top_parent_ppids": dict(parent_counter.most_common(10)),
            "start_time": start_time,
            "end_time": end_time,
        }

        return {"entries": entries, "summary": summary}

    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> Any:
        if query_type == "process_list":
            limit = int(kwargs.get("limit", 25))
            return {
                "total": len(log_entries),
                "sample": [
                    {
                        "timestamp": e.get("timestamp"),
                        "name": e.get("process_name"),
                        "pid": e.get("process_id"),
                        "ppid": e.get("parent_process_id"),
                        "image": e.get("image"),
                    }
                    for e in log_entries[:limit]
                ],
            }

        elif query_type == "count_by_name":
            c = Counter(e.get("process_name") for e in log_entries)
            return dict(c.most_common(20))

        elif query_type == "children_of":
            parent = kwargs.get("ppid")
            if parent is None:
                raise ValueError("children_of requires 'ppid' parameter")
            parent = int(parent)
            children = [
                {
                    "timestamp": e.get("timestamp"),
                    "pid": e.get("process_id"),
                    "name": e.get("process_name"),
                    "cmd": e.get("command_line"),
                }
                for e in log_entries
                if int(e.get("parent_process_id", -1)) == parent
            ]
            return {"ppid": parent, "children": children, "count": len(children)}

        elif query_type == "tree_from_pid":
            root = kwargs.get("pid")
            if root is None:
                raise ValueError("tree_from_pid requires 'pid' parameter")
            root = int(root)
            # Build adjacency
            by_ppid = defaultdict(list)
            by_pid = {}
            for e in log_entries:
                by_pid[int(e.get("process_id", -1))] = e
                by_ppid[int(e.get("parent_process_id", -1))].append(e)

            def build(node_pid: int, depth: int = 0, max_depth: int = 10):
                if depth > max_depth:
                    return None
                node = by_pid.get(node_pid)
                if not node:
                    return None
                children = [build(int(c.get("process_id")), depth + 1, max_depth) for c in by_ppid.get(node_pid, [])]
                children = [c for c in children if c]
                return {
                    "pid": node_pid,
                    "name": node.get("process_name"),
                    "image": node.get("image"),
                    "cmd": node.get("command_line"),
                    "children": children,
                }

            return build(root) or {"pid": root, "children": []}

        elif query_type == "top_parents":
            c = Counter(int(e.get("parent_process_id", -1)) for e in log_entries)
            return dict(c.most_common(10))

        elif query_type == "commandline_search":
            term = str(kwargs.get("term", "")).lower()
            if not term:
                return {"matches": [], "count": 0}
            matches = [
                {
                    "timestamp": e.get("timestamp"),
                    "pid": e.get("process_id"),
                    "name": e.get("process_name"),
                    "cmd": e.get("command_line"),
                }
                for e in log_entries
                if term in str(e.get("command_line", "")).lower()
            ]
            return {"count": len(matches), "matches": matches[:50]}

        elif query_type == "suspicious_spawns":
            # Heuristics: Office spawning PowerShell/cmd/wscript; browsers spawning shells; unsigned binaries (missing md5) spawning network tools
            suspicious_children = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
            suspicious_parents = {"winword.exe", "excel.exe", "outlook.exe", "chrome.exe", "firefox.exe", "edge.exe"}
            hits = []
            for e in log_entries:
                parent = str(e.get("parent_process_id", ""))
                # find parent name
                parent_name = next((p.get("process_name") for p in log_entries if str(p.get("process_id")) == parent), "")
                child_name = (e.get("process_name") or "").lower()
                if parent_name and parent_name.lower() in suspicious_parents and child_name in suspicious_children:
                    hits.append({
                        "timestamp": e.get("timestamp"),
                        "ppid": int(parent),
                        "parent_name": parent_name,
                        "pid": e.get("process_id"),
                        "child_name": e.get("process_name"),
                        "cmd": e.get("command_line"),
                    })
            return {"count": len(hits), "events": hits[:50]}

        else:
            raise ValueError(f"Unsupported query type: {query_type}")
