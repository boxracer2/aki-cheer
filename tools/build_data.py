"""Turn the public AKI Cheer Google Calendar into the team page's schedule file (data.json).
Runs in GitHub Actions every 30 minutes. If the CLASS_CODE secret is set, the file is encrypted with the
same scheme as the page (AES-256-GCM, PBKDF2-SHA256 250k); otherwise it is written as plain JSON.
The file is only rewritten when the schedule itself changes."""
import os, re, json, base64, hashlib, datetime, urllib.request
from zoneinfo import ZoneInfo
from icalendar import Calendar

ICS = "https://calendar.google.com/calendar/ical/a18ba84dfe9e3998b38fb2a782774ac43d306addbf143895fd3e6201d75ac041%40group.calendar.google.com/public/basic.ics"
TZ = ZoneInfo("America/Phoenix")
OUT = os.path.join(os.path.dirname(__file__), "..", "data.json")

def clean_title(t):
    t = re.sub(r"^UNCONFIRMED:\s*", "", t)
    t = re.sub(r"^\d{1,2}:\d{2}\s*[AP]M:\s*", "", t)
    t = re.sub(r"\s*\((end time )?UNCONFIRMED\)", "", t, flags=re.I)
    t = re.sub(r"\s*\(GRADE CHECK\)", "", t, flags=re.I)
    t = re.sub(r"\s*/\s*Grade Check$", "", t, flags=re.I)
    t = re.sub(r"^Practice - (\w)", lambda m: "Practice: " + m.group(1).lower(), t)
    t = t.replace(" / ", ", ").replace(" - ", ": ")
    return t

def clean_note(desc, kind):
    if not desc or kind == "g": return ""
    keep = []
    for para in re.split(r"\n\s*\n", desc.strip()):
        if para.startswith("Source:"): continue
        para = re.sub(r"\s*Google Class(room)? code:\s*\w+\.?", "", para).strip()
        para = re.sub(r"^Grade check day\.?$", "", para).strip()
        if para: keep.append(para)
    return " ".join(keep)

def kind_of(title, all_day, start):
    tl = title.lower()
    if re.search(r"no school|no practice|holiday", tl): return "x"
    if "unconfirmed" in tl and re.search(r"practice or game|tournament", tl): return "g"
    if all_day and "order" in tl: return "d"
    if "practice" in tl and not all_day and start.hour < 9: return "p"
    return "e"

def build():
    import time
    for attempt in range(5):
        try:
            raw = urllib.request.urlopen(ICS, timeout=30).read(); break
        except Exception as e:
            if attempt == 4: raise
            print(f"Calendar fetch failed ({e}); retrying."); time.sleep(10 * (attempt + 1))
    cal = Calendar.from_ical(raw)
    out = []
    for ev in cal.walk("VEVENT"):
        if str(ev.get("STATUS", "CONFIRMED")).upper() == "CANCELLED": continue
        title = str(ev.get("SUMMARY", "")).strip()
        st, en = ev.decoded("DTSTART"), ev.decoded("DTEND") if ev.get("DTEND") else None
        all_day = not isinstance(st, datetime.datetime)
        if not all_day: st = st.astimezone(TZ); en = en.astimezone(TZ) if en else None
        k = kind_of(title, all_day, st)
        flag = ""
        if re.search(r"grade check", title, re.I): flag = "gc"
        elif re.search(r"cheer showcase$|stunting clinic|picture day|pep assembly", title, re.I): flag = "big"
        loc = str(ev.get("LOCATION", "")).strip()
        game = bool(re.search(r"\bgames?\b|\bvs\.?\s|\btournament", title, re.I)) and "unconfirmed" not in title.lower() and not all_day
        days = 1
        if all_day and en: days = max(1, (en - st).days)
        for i in range(days):
            d = st if not all_day else st + datetime.timedelta(days=i)
            out.append({
                "d": d.strftime("%Y-%m-%d"),
                "s": "" if all_day else st.strftime("%H:%M"),
                "e": "" if all_day or not en else en.strftime("%H:%M"),
                "t": clean_title(title), "k": k, "n": clean_note(str(ev.get("DESCRIPTION", "")), k),
                "flag": flag, "where": "" if k in "xdg" else loc, "game": game,
            })
    out.sort(key=lambda e: (e["d"], e["s"] or "00:00", e["t"]))
    return out

def encrypt(obj, code):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=250000).derive(code.strip().lower().encode())
    ct = AESGCM(key).encrypt(iv, json.dumps(obj).encode(), None)
    b = lambda x: base64.b64encode(x).decode()
    return {"s": b(salt), "i": b(iv), "n": 250000, "c": b(ct)}

if __name__ == "__main__":
    events = build()
    digest = hashlib.sha256(json.dumps(events, sort_keys=True).encode()).hexdigest()[:16]
    code = os.environ.get("CLASS_CODE", "")
    try:
        prev = json.load(open(OUT)); old, old_locked = prev.get("v"), "enc" in prev
    except Exception: old, old_locked = None, None
    if old == digest and old_locked == bool(code):
        print("No schedule change."); raise SystemExit(0)
    payload = {"events": events, "updated": datetime.datetime.now(TZ).strftime("%b %-d, %Y %-I:%M %p")}
    doc = {"v": digest, "enc": encrypt(payload, code)} if code else {"v": digest, **payload}
    json.dump(doc, open(OUT, "w"))
    print(f"Wrote {len(events)} entries ({'encrypted' if code else 'plain'}), version {digest}.")
