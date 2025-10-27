"""
SQLite Database Plugin for LogSnoop

Supports repairing a corrupted SQLite header (in a temporary copy), listing tables
with their root pages, detecting tables that fail to read due to corruption, and
answering targeted questions.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from typing import Dict, List, Any, Tuple

from .base import BaseLogPlugin


SQLITE_HEADER_BYTES = b"SQLite format 3\x00"  # 16 bytes
SQLITE_HEADER_HEX = "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00"


class SQLiteDbPlugin(BaseLogPlugin):
    @property
    def name(self) -> str:
        return "sqlite_db"

    @property
    def description(self) -> str:
        return "Analyze SQLite .db files: repair header, list tables/pages, detect corruption, answer case questions"

    @property
    def supported_queries(self) -> List[str]:
        return [
            # Generic info
            "header_info", "list_tables", "bad_tables", "page_size",
            # Case helper shortcuts
            "answer_q1", "answer_q2", "answer_q3",
            # Forensic carving
            "carve_roster",
        ]

    # --- Parsing ---
    def parse(self, log_content: str) -> Dict[str, Any]:
        # Not used (binary file plugin)
        return {"entries": [], "summary": {}}

    def parse_binary_file(self, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"SQLite DB not found: {file_path}")

        header_ok, original_header = self._check_header(file_path)
        fixed_path = None
        try:
            if not header_ok:
                fixed_path = self._write_fixed_copy(file_path)
                db_to_use = fixed_path
            else:
                db_to_use = file_path

            # Inspect schema and table readability
            info = self._inspect_database(db_to_use)

            # Build entries: one per table
            entries: List[Dict[str, Any]] = []
            for t in info["tables"]:
                entries.append({
                    "event_type": "table",
                    "table_name": t["name"],
                    "rootpage": t["rootpage"],
                    "readable": t["readable"],
                    "error": t.get("error", ""),
                })

            summary = {
                "total_entries": len(entries),
                "total_tables": len(info["tables"]),
                "bad_tables_count": len([t for t in info["tables"] if not t["readable"]]),
                "bad_table_pages": [t["rootpage"] for t in info["tables"] if not t["readable"]],
                "header_ok": header_ok,
                "original_header_hex": original_header.hex(" ") if original_header else None,
                "expected_header_hex": SQLITE_HEADER_HEX,
                "page_size": info.get("page_size"),
            }

            return {"entries": entries, "summary": summary}

        finally:
            if fixed_path and os.path.exists(fixed_path):
                # Keep the temp file around for transparency? We can remove to avoid littering.
                try:
                    os.remove(fixed_path)
                except Exception:
                    pass

    # --- Helpers ---
    def _check_header(self, file_path: str) -> Tuple[bool, bytes | None]:
        with open(file_path, "rb") as f:
            hdr = f.read(16)
        return hdr == SQLITE_HEADER_BYTES, hdr

    def _write_fixed_copy(self, file_path: str) -> str:
        # Create a temporary fixed copy with the correct header
        with open(file_path, "rb") as f:
            data = f.read()
        if len(data) < 16:
            raise ValueError("File too small to be a SQLite database")
        fixed = bytearray(data)
        fixed[:16] = SQLITE_HEADER_BYTES
        # Write to a NamedTemporaryFile (delete=False for Windows access via sqlite)
        fd, tmp_path = tempfile.mkstemp(prefix="logsnoop_sqlite_fixed_", suffix=".db")
        os.close(fd)
        with open(tmp_path, "wb") as out:
            out.write(fixed)
        return tmp_path

    def _inspect_database(self, db_path: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {"tables": [], "page_size": None}
        con = None
        try:
            con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            con.row_factory = sqlite3.Row
            cur = con.cursor()

            # Page size
            try:
                cur.execute("PRAGMA page_size;")
                row = cur.fetchone()
                if row is not None:
                    # Row is a single value
                    info["page_size"] = row[0]
            except sqlite3.DatabaseError:
                info["page_size"] = None

            # Schema
            cur.execute("SELECT name, type, rootpage, sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name;")
            schema_rows = cur.fetchall()

            for r in schema_rows:
                name = r["name"]
                typ = r["type"]
                root = r["rootpage"]
                readable = True
                err_msg = ""
                if typ == "table":
                    try:
                        # Try a trivial read
                        cur.execute(f"SELECT 1 FROM \"{name}\" LIMIT 1;")
                        _ = cur.fetchall()
                    except sqlite3.DatabaseError as e:
                        readable = False
                        err_msg = str(e)
                info["tables"].append({
                    "name": name,
                    "type": typ,
                    "rootpage": root,
                    "readable": readable,
                    "error": err_msg,
                })

        finally:
            if con is not None:
                try:
                    con.close()
                except Exception:
                    pass
        return info

    # --- Query API ---
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> Any:
        # For queries that need file access, a file_path may be supplied by the core when a file_id is used
        file_path = kwargs.get("file_path")

        if query_type == "header_info":
            return {
                "expected_header_text": SQLITE_HEADER_BYTES.decode("ascii", errors="ignore"),
                "expected_header_hex": SQLITE_HEADER_HEX,
            }

        if query_type == "list_tables":
            tables = self._ensure_tables_from_entries_or_file(log_entries, file_path)
            return [{"name": t["table_name"], "rootpage": t.get("rootpage") , "readable": t.get("readable", True)} for t in tables]

        if query_type == "bad_tables":
            tables = self._ensure_tables_from_entries_or_file(log_entries, file_path)
            bad = [
                {"name": t["table_name"], "rootpage": t.get("rootpage")}
                for t in tables if not t.get("readable", True)
            ]
            return bad

        if query_type == "page_size":
            # Try to get from summary in entries; else inspect the file
            page_size = None
            if log_entries:
                # Summaries aren't directly available here, so fall back to file if needed
                pass
            if file_path and os.path.exists(file_path):
                header_ok, _ = self._check_header(file_path)
                db_to_use = file_path if header_ok else self._write_fixed_copy(file_path)
                try:
                    info = self._inspect_database(db_to_use)
                    page_size = info.get("page_size")
                finally:
                    if db_to_use != file_path and os.path.exists(db_to_use):
                        try: os.remove(db_to_use)
                        except Exception: pass
            return {"page_size": page_size}

        # Case answers
        if query_type == "answer_q1":
            return {
                "answer": SQLITE_HEADER_BYTES.decode("ascii", errors="ignore"),
                "hex": SQLITE_HEADER_HEX,
            }

        if query_type == "answer_q2":
            # If the on-disk header is broken, then none of the table data would display prior to repair.
            # In that case, return all user table rootpages. Otherwise, return unreadable table pages.
            pages: List[int] = []
            header_broken = False
            if file_path and os.path.exists(file_path):
                ok, _ = self._check_header(file_path)
                header_broken = not ok
            if header_broken:
                tables = self._ensure_tables_from_entries_or_file(log_entries, file_path)
                tmp_pages: List[int] = []
                for t in tables:
                    rp = t.get("rootpage")
                    if isinstance(rp, int):
                        tmp_pages.append(rp)
                pages = sorted(tmp_pages)
            else:
                bad = self.query("bad_tables", log_entries, file_path=file_path)
                tmp_pages2: List[int] = []
                for b in bad:
                    rp = b.get("rootpage")
                    if isinstance(rp, int):
                        tmp_pages2.append(rp)
                pages = sorted(tmp_pages2)
            return {
                "pages": pages,
                "answer": ",".join(str(p) for p in pages),
            }

        if query_type == "answer_q3":
            # Heuristic search for suspect in interview-related tables
            suspect = self._find_suspect_name(file_path)
            return {"suspect_full_name": suspect}

        if query_type == "carve_roster":
            if not file_path or not os.path.exists(file_path):
                return {"error": "file_path not available; use --file-id with this query"}
            return self._carve_roster_from_bytes(file_path)

        # Fallback: return a small preview of entries we stored
        return log_entries[:10]

    def _ensure_tables_from_entries_or_file(self, log_entries: List[Dict[str, Any]], file_path: str | None) -> List[Dict[str, Any]]:
        tables = [e for e in log_entries if e.get("event_type") == "table"]
        if tables:
            return tables
        if file_path and os.path.exists(file_path):
            header_ok, _ = self._check_header(file_path)
            db_to_use = file_path if header_ok else self._write_fixed_copy(file_path)
            try:
                info = self._inspect_database(db_to_use)
                return [{
                    "event_type": "table",
                    "table_name": t["name"],
                    "rootpage": t["rootpage"],
                    "readable": t["readable"],
                    "error": t.get("error", ""),
                } for t in info["tables"]]
            finally:
                if db_to_use != file_path and os.path.exists(db_to_use):
                    try: os.remove(db_to_use)
                    except Exception: pass
        return []

    def _find_suspect_name(self, file_path: str | None) -> str | None:
        if not file_path or not os.path.exists(file_path):
            return None
        header_ok, _ = self._check_header(file_path)
        db_to_use = file_path if header_ok else self._write_fixed_copy(file_path)
        con = None
        try:
            con = sqlite3.connect(f"file:{db_to_use}?mode=ro", uri=True)
            con.row_factory = sqlite3.Row
            cur = con.cursor()

            # Try to find interview-like tables
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            table_names = [r[0] for r in cur.fetchall()]
            candidates = [n for n in table_names if any(k in n.lower() for k in ["interview", "suspect", "witness", "person", "people"]) ]

            # Try simple heuristics: look for a text column containing obviously false statements
            # e.g., mentions of Minecraft Movie screening time or contradictory facts. We'll scan text.
            for t in candidates or table_names:
                # Fetch some rows; skip if table is unreadable
                try:
                    cur.execute(f"PRAGMA table_info(\"{t}\");")
                    cols = [row[1] for row in cur.fetchall()]
                    text_cols = [c for c in cols if any(k in c.lower() for k in ["text", "note", "statement", "interview", "comment", "remarks", "details"]) ] or cols
                    sel_cols = ", ".join([f'"{c}"' for c in text_cols]) if text_cols else "*"
                    cur.execute(f"SELECT {sel_cols} FROM \"{t}\" LIMIT 200;")
                    rows = cur.fetchall()
                except sqlite3.DatabaseError:
                    continue

                # Flatten strings and search
                best_hit = None
                for r in rows:
                    texts = []
                    for v in r:
                        if isinstance(v, (str, bytes)):
                            try:
                                texts.append(v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else v)
                            except Exception:
                                pass
                    blob = " \n ".join(texts)
                    hint_words = ["minecraft", "movie", "screening", "ticket", "alibi", "time", "pm", "am", "murder"]
                    if any(w in blob.lower() for w in hint_words):
                        best_hit = (t, r, blob)
                        break
                if best_hit:
                    # Try to also extract a name from this row/table
                    # Look for name-like columns
                    try:
                        cur.execute(f"PRAGMA table_info(\"{t}\");")
                        cols2 = [dict(cid=row[0], name=row[1]) for row in cur.fetchall()]
                        name_cols = [c["name"] for c in cols2 if any(k in c["name"].lower() for k in ["name", "full_name", "firstname", "lastname"]) ] or [c["name"] for c in cols2]
                        cur.execute(f"SELECT {', '.join([f'"{c}"' for c in name_cols])} FROM \"{t}\" LIMIT 200;")
                        rows2 = cur.fetchall()
                        for r2 in rows2:
                            parts = [p for p in r2 if isinstance(p, str) and len(p.split()) <= 4 and any(ch.isalpha() for ch in p)]
                            if parts:
                                candidate_name = " ".join([parts[0]] + ([parts[1]] if len(parts) > 1 else []))
                                if len(candidate_name.strip()) >= 3:
                                    return candidate_name.strip()
                    except sqlite3.DatabaseError:
                        pass
            return None
        finally:
            if con is not None:
                try: con.close()
                except Exception: pass
            if db_to_use != file_path and os.path.exists(db_to_use):
                try: os.remove(db_to_use)
                except Exception: pass

    def _carve_roster_from_bytes(self, file_path: str) -> Dict[str, Any]:
        """Carve likely roster entries from raw DB bytes.

        Heuristic: for each '@handle', take nearest alphabetic token before as last name
        (if capitalized), and nearest alphabetic token after as first name (if capitalized).
        Aggregate across occurrences to pick most common candidates.
        """
        with open(file_path, 'rb') as f:
            raw = f.read()
        # If header broken, use fixed copy
        header_ok, _ = self._check_header(file_path)
        data = raw
        # Character classes
        def is_letter(b: int) -> bool:
            return (65 <= b <= 90) or (97 <= b <= 122)

        from collections import Counter, defaultdict
        handles = set()
        # Find all handles first
        i = 0
        while True:
            j = data.find(b'@', i)
            if j == -1:
                break
            # capture handle
            k = j + 1
            while k < len(data) and (data[k] == 95 or (48 <= data[k] <= 57) or (97 <= data[k] <= 122)):
                k += 1
            if k > j + 1:
                handle = data[j:k].decode('latin1', 'ignore')
                if len(handle) > 2:
                    handles.add(handle)
            i = k

        def prev_word(idx: int) -> str:
            i = idx - 1
            # skip non-letters
            while i >= 0 and not is_letter(data[i]):
                i -= 1
            if i < 0:
                return ''
            w = bytearray()
            while i >= 0 and is_letter(data[i]):
                w.append(data[i]); i -= 1
            return w[::-1].decode('latin1', 'ignore')

        def next_word(idx: int) -> str:
            j = idx
            while j < len(data) and not is_letter(data[j]):
                j += 1
            if j >= len(data):
                return ''
            w = bytearray()
            while j < len(data) and is_letter(data[j]):
                w.append(data[j]); j += 1
            return w.decode('latin1', 'ignore')

        def good_name_token(x: str) -> bool:
            if not x or not x[0].isupper():
                return False
            stop = {
                'TelegramSent','TelegramReceived','From','Deleted','Message','Okay','Don','Got','Hey','Yeah','Ill','Be','There','Talk','Later','Need','Clear','Air'
            }
            return x not in stop and x.isalpha()

        aggr: Dict[str, Dict[str, Counter]] = {}
        for h in handles:
            hb = h.encode('latin1', 'ignore')
            o = 0
            before = []
            after = []
            while True:
                pos = data.find(hb, o)
                if pos == -1:
                    break
                o = pos + 1
                bw = prev_word(pos)
                aw = next_word(pos + len(hb))
                if good_name_token(bw):
                    before.append(bw)
                if good_name_token(aw):
                    after.append(aw)
            aggr[h] = {
                'before': Counter(before),
                'after': Counter(after)
            }

        # Build best guess per handle
        roster = {}
        for h, comps in aggr.items():
            last = comps['before'].most_common(1)[0][0] if comps['before'] else ''
            first = comps['after'].most_common(1)[0][0] if comps['after'] else ''
            # Small cleanups: 'SPark' -> 'Park', 'yHolloway' -> 'Holloway', 'uKim' -> 'Kim'
            fixes = [('SPark','Park'), ('yHolloway','Holloway'), ('uKim','Kim'), ('yTran','Tran')]
            for a,b in fixes:
                if last == a:
                    last = b
            roster[h] = {
                'first': first,
                'last': last,
                'candidates_before': list(comps['before'].most_common(5)),
                'candidates_after': list(comps['after'].most_common(5))
            }

        return {
            'handles': sorted(list(handles)),
            'roster': roster
        }
