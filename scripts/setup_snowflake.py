"""Runs sql/01..07 in order against the Snowflake account in your environment.

  python scripts/setup_snowflake.py            run everything (needs an admin role, e.g. ACCOUNTADMIN on a trial)
  python scripts/setup_snowflake.py --dry-run  print the statements without running them

Statements are split on ';' at line ends. Comment-only lines are skipped. Stop-on-error: fix the file, rerun;
every statement uses IF NOT EXISTS or CREATE OR REPLACE, so reruns are safe."""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv(path: Path | None = None) -> None:
    p = path or (ROOT / ".env")
    if p.is_file():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"'))


def split_statements(sql: str) -> list[str]:
    """Split on ';' at line ends (ignoring trailing comments), except inside $$ ... $$ blocks (stored procedures)."""
    out, buf, in_block = [], [], False
    for line in sql.splitlines():
        stripped = line.strip()
        if not in_block and (not stripped or stripped.startswith("--")):
            continue
        buf.append(line)
        if stripped.count("$$") % 2 == 1:
            in_block = not in_block
        if not in_block:
            code_line = re.sub(r"--.*$", "", stripped).strip()
            if code_line.endswith(";"):
                last_line = buf[-1]
                last_no_comment = re.sub(r"--.*$", "", last_line).rstrip()
                if last_no_comment.endswith(";"):
                    buf[-1] = last_no_comment[:-1].rstrip()
                stmt = "\n".join(buf).rstrip()
                if stmt.strip():
                    out.append(stmt)
                buf = []
    if buf:
        stmt = "\n".join(buf).rstrip()
        if stmt.strip():
            out.append(stmt)
    return out


def main() -> int:
    _load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    files = sorted((ROOT / "sql").glob("*.sql"))
    plan = [(f.name, split_statements(f.read_text())) for f in files]
    if a.dry_run:
        for name, stmts in plan:
            print(f"-- {name}: {len(stmts)} statements")
        return 0
    try:
        import snowflake.connector  # type: ignore
    except ImportError:
        print("pip install snowflake-connector-python", file=sys.stderr)
        return 2
    missing = [k for k in ("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PASSWORD") if not os.environ.get(k)]
    if missing:
        print("missing: " + ", ".join(missing), file=sys.stderr)
        return 2
    conn = snowflake.connector.connect(account=os.environ["SNOWFLAKE_ACCOUNT"], user=os.environ["SNOWFLAKE_USER"],
                                       password=os.environ["SNOWFLAKE_PASSWORD"],
                                       role=os.environ.get("SNOWFLAKE_SETUP_ROLE", "ACCOUNTADMIN"))
    cur = conn.cursor()
    for name, stmts in plan:
        for i, stmt in enumerate(stmts, 1):
            try:
                cur.execute(stmt)
            except Exception as e:
                print(f"FAILED {name} statement {i}: {e}\n{stmt[:300]}", file=sys.stderr)
                return 1
        print(f"ok  {name} ({len(stmts)} statements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
