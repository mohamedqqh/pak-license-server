#!/usr/bin/env python3
"""
abozain.py - Admin CLI for PAK License Server
إدارة المفاتيح من سطر الأوامر
"""
import sys
import os
import argparse
import requests
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

# ==================== CONFIG ====================
DEFAULT_SERVER = os.getenv("SERVER_URL", "http://localhost:8000")
DEFAULT_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

G = Fore.GREEN
R = Fore.RED
Y = Fore.YELLOW
C = Fore.CYAN
M = Fore.MAGENTA
W = Fore.WHITE
B = Style.BRIGHT
RS = Style.RESET_ALL


# ==================== HELPERS ====================
def banner():
    print(f"""{C}{B}
==============================================================
              PAK LICENSE SERVER - ADMIN CLI
                     by Abozain
=============================================================={RS}
""")


def api_call(method, path, server, password, payload=None, params=None):
    url = server.rstrip("/") + path
    if params is None:
        params = {}
    params["password"] = password

    try:
        if method == "GET":
            r = requests.get(url, params=params, timeout=10)
        elif method == "POST":
            body = {"admin_password": password}
            if payload:
                body.update(payload)
            r = requests.post(url, json=body, params=params, timeout=10)
        else:
            raise ValueError("Bad method")
    except requests.exceptions.ConnectionError:
        print(f"{R}[!] Cannot reach server: {server}{RS}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"{R}[!] Server timeout{RS}")
        sys.exit(1)

    try:
        data = r.json()
    except Exception:
        print(f"{R}[!] Invalid response (HTTP {r.status_code}){RS}")
        print(f"{R}    {r.text[:200]}{RS}")
        sys.exit(1)

    if r.status_code == 403:
        print(f"{R}[!] Wrong password{RS}")
        sys.exit(1)
    if r.status_code == 404:
        print(f"{Y}[!] {data.get('error', 'Not found')}{RS}")
        sys.exit(1)
    if r.status_code >= 400:
        print(f"{R}[!] Error: {data.get('error', data)}{RS}")
        sys.exit(1)

    return data


def fmt_date(iso):
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso or "?"


def days_left(iso):
    try:
        d = datetime.fromisoformat(iso) - datetime.now()
        return d.days
    except Exception:
        return "?"


# ==================== COMMANDS ====================
def cmd_create(args):
    r = api_call("POST", "/api/admin/create", args.server, args.password, {
        "username": args.username,
        "days": args.days,
        "note": args.note or "",
    })
    print(f"\n{G}{B}[+] KEY CREATED{RS}")
    print(f"    {C}Key:      {W}{B}{r['key']}{RS}")
    print(f"    {C}Username: {W}{r['username']}{RS}")
    print(f"    {C}Expiry:   {W}{r['expiry'][:10]}{RS}")
    print(f"    {C}Days:     {W}{r['days']}{RS}\n")


def cmd_list(args):
    r = api_call("GET", "/api/admin/list", args.server, args.password)
    keys = r["keys"]
    if not keys:
        print(f"{Y}[!] No keys found{RS}")
        return

    print(f"\n{C}{B}=== ALL KEYS ({len(keys)}) ==={RS}\n")
    print(f"{B}{'#':<3} {'KEY':<20} {'USERNAME':<15} {'EXPIRY':<12} {'DAYS':<6} {'STATUS':<10}{RS}")
    print("-" * 80)
    for i, k in enumerate(keys, 1):
        active = k.get("active", 1)
        left = days_left(k["expiry"])
        if not active:
            status = f"{R}DISABLED{RS}"
        elif isinstance(left, int) and left < 0:
            status = f"{R}EXPIRED{RS}"
        elif isinstance(left, int) and left <= 3:
            status = f"{Y}EXPIRING{RS}"
        else:
            status = f"{G}ACTIVE{RS}"

        hwid_status = f"{G}✓{RS}" if k.get("hwid") else f"{Y}—{RS}"
        print(f"{i:<3} {k['key']:<20} {k['username']:<15} {k['expiry'][:10]:<12} {str(left):<6} {status} {hwid_status}")
    print()


def cmd_live(args):
    r = api_call("GET", "/api/admin/live", args.server, args.password)
    sessions = r["sessions"]
    n = r["online_now"]

    if n == 0:
        print(f"\n{Y}🔴 ONLINE NOW: 0 users{RS}\n")
        return

    print(f"\n{G}{B}🟢 ONLINE NOW: {n} user(s){RS}\n")
    print(f"{B}{'#':<3} {'USERNAME':<15} {'KEY':<20} {'IP':<18} {'SINCE':<18}{RS}")
    print("-" * 80)
    for i, s in enumerate(sessions, 1):
        since = fmt_date(s.get("created_at", ""))
        print(f"{i:<3} {s.get('username', '?'):<15} {s['key']:<20} {s.get('ip', '?'):<18} {since:<18}")
    print()


def cmd_stats(args):
    r = api_call("GET", "/api/admin/stats", args.server, args.password)
    s = r["stats"]
    print(f"\n{C}{B}=== STATS ==={RS}\n")
    print(f"    {C}Total Keys:      {W}{B}{s['total_keys']}{RS}")
    print(f"    {G}Active Keys:     {W}{B}{s['active_keys']}{RS}")
    print(f"    {R}Expired Keys:    {W}{B}{s['expired_keys']}{RS}")
    print(f"    {M}Live Now:        {W}{B}{s['live_now']}{RS}\n")


def cmd_revoke(args):
    api_call("POST", "/api/admin/revoke", args.server, args.password, {"key": args.key.upper()})
    print(f"{G}[+] Key revoked: {args.key.upper()}{RS}")


def cmd_extend(args):
    r = api_call("POST", "/api/admin/extend", args.server, args.password, {
        "key": args.key.upper(),
        "days": args.days,
    })
    print(f"{G}[+] Extended {args.key.upper()} by {args.days} days{RS}")
    print(f"    New expiry: {r['new_expiry'][:10]}{RS}")


def cmd_toggle(args):
    active = (args.action == "enable")
    r = api_call("POST", "/api/admin/toggle", args.server, args.password, {
        "key": args.key.upper(),
        "active": active,
    })
    state = f"{G}ENABLED{RS}" if active else f"{R}DISABLED{RS}"
    print(f"[+] Key {args.key.upper()} is now {state}")


def cmd_reset_hwid(args):
    api_call("POST", "/api/admin/reset-hwid", args.server, args.password, {"key": args.key.upper()})
    print(f"{G}[+] HWID reset for {args.key.upper()}{RS}")


def cmd_logs(args):
    r = api_call("GET", "/api/admin/logs", args.server, args.password, params={"limit": args.limit})
    logs = r["logs"]
    print(f"\n{C}{B}=== LAST {len(logs)} LOGS ==={RS}\n")
    for l in logs:
        action = l["action"]
        if "denied" in action or action == "revoke":
            color = R
        elif action.endswith("_ok"):
            color = G
        else:
            color = Y
        ts = fmt_date(l["timestamp"])
        print(f"{color}{ts}{RS} | {B}{action:<20}{RS} | {l.get('key', '')[:20]:<20} | {l.get('detail', '')[:30]}")
    print()


def cmd_health(args):
    try:
        r = requests.get(args.server.rstrip("/") + "/api/health", timeout=10)
        data = r.json()
        print(f"{G}[+] Server: {args.server}{RS}")
        print(f"    Status: {data.get('status')}")
        print(f"    Live now: {data.get('live_now', 0)}")
    except Exception as e:
        print(f"{R}[!] Error: {e}{RS}")


# ==================== MAIN ====================
def build_parser():
    parser = argparse.ArgumentParser(
        description="Abozain Admin CLI for PAK License Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python abozain.py create Ahmed 30
  python abozain.py create Sara 365 --note "VIP"
  python abozain.py live
  python abozain.py list
  python abozain.py stats
  python abozain.py revoke BT-ABC123
  python abozain.py extend BT-ABC123 30
  python abozain.py enable BT-ABC123
  python abozain.py disable BT-ABC123
  python abozain.py reset-hwid BT-ABC123
  python abozain.py logs
  python abozain.py health
"""
    )
    parser.add_argument("--server", default=DEFAULT_SERVER, help="Server URL")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="Admin password")

    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("create", help="Create a new key")
    p.add_argument("username")
    p.add_argument("days", type=int)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_create)

    sub.add_parser("list", help="List all keys").set_defaults(func=cmd_list)
    sub.add_parser("live", help="Show who is online now").set_defaults(func=cmd_live)
    sub.add_parser("stats", help="Show statistics").set_defaults(func=cmd_stats)
    sub.add_parser("health", help="Server health").set_defaults(func=cmd_health)

    p = sub.add_parser("revoke", help="Delete a key")
    p.add_argument("key")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("extend", help="Extend key expiry")
    p.add_argument("key")
    p.add_argument("days", type=int)
    p.set_defaults(func=cmd_extend)

    p = sub.add_parser("enable", help="Enable a key")
    p.add_argument("key")
    p.set_defaults(func=cmd_toggle, action="enable")

    p = sub.add_parser("disable", help="Disable a key")
    p.add_argument("key")
    p.set_defaults(func=cmd_toggle, action="disable")

    p = sub.add_parser("reset-hwid", help="Reset HWID (allow new device)")
    p.add_argument("key")
    p.set_defaults(func=cmd_reset_hwid)

    p = sub.add_parser("logs", help="Show recent logs")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_logs)

    return parser


def main():
    banner()
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if not args.password:
        print(f"{R}[!] No admin password provided.{RS}")
        print(f"    Use: python abozain.py --password YOUR_PASS ...")
        print(f"    Or set ADMIN_PASSWORD env variable")
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
