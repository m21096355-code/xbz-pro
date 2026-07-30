import os, json, uuid, sqlite3, secrets, base64, time
from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify, Response
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_USER = os.environ.get("ADMIN_USER", "xbz")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "xbz2026")
DB = "xbz.db"
VERSION = "1.7.6"

def init_db():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS inbounds (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT DEFAULT '',
        protocol TEXT DEFAULT 'vless', port INTEGER DEFAULT 443, uuid TEXT,
        flow TEXT DEFAULT '', network TEXT DEFAULT 'ws', security TEXT DEFAULT 'none',
        sni TEXT DEFAULT '', domain TEXT DEFAULT '', host TEXT DEFAULT '',
        path TEXT DEFAULT '/', remark TEXT DEFAULT '', enable INTEGER DEFAULT 1,
        tag TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS users_vpn (
        id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, uuid TEXT,
        enable INTEGER DEFAULT 1, up INTEGER DEFAULT 0, down INTEGER DEFAULT 0,
        total INTEGER DEFAULT 0, expiry INTEGER DEFAULT 0, inbound_id INTEGER,
        limit_ip INTEGER DEFAULT 0, tg_id TEXT DEFAULT '', comment TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP DEFAULT '')""")
    c.execute("""CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)""")
    for k, v in [("panel_title","XBZ PRO"),("server_domain","your-domain.com"),
                  ("server_port","443"),("sub_path","/sub")]:
        c.execute("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)", (k,v))
    c.commit(); c.close()

def get_db():
    conn = sqlite3.connect(DB); conn.row_factory = sqlite3.Row; return conn

def gs(key, default=""):
    db = get_db(); r = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    db.close(); return r["value"] if r else default

def ss(key, value):
    db = get_db(); db.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, value))
    db.commit(); db.close()

def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get("logged_in"): return redirect(url_for("login"))
        return f(*a, **kw)
    return d

@app.route("/login", methods=["GET","POST"])
def login():
    err = None
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USER and request.form.get("password") == ADMIN_PASS:
            session["logged_in"] = True; return redirect(url_for("dashboard"))
        err = "نام کاربری یا رمز اشتباه است"
    return render_template_string(LOGIN_HTML, error=err)

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    db = get_db()
    inbounds = db.execute("SELECT * FROM inbounds ORDER BY id DESC").fetchall()
    users = db.execute("""SELECT u.*, i.name as inb_name, i.port as inb_port,
        i.protocol as inb_proto, i.domain as inb_domain, i.sni as inb_sni,
        i.network as inb_net, i.security as inb_sec
        FROM users_vpn u LEFT JOIN inbounds i ON u.inbound_id=i.id ORDER BY u.id DESC""").fetchall()
    tu = len(users); au = sum(1 for u in users if u["enable"])
    tdn = sum(u["down"]+u["up"] for u in users); ti = len(inbounds)
    now = time.time()
    expired = sum(1 for u in users if u["expiry"] and u["expiry"] < now)
    db.close()
    return render_template_string(DASH_HTML, inbounds=inbounds, users=users,
        total_users=tu, active_users=au, expired_users=expired, total_data=tdn,
        total_inbounds=ti, version=VERSION, panel_name=gs("panel_title"))

@app.route("/settings", methods=["GET","POST"])
@login_required
def settings_page():
    if request.method == "POST":
        for key in ["panel_title","server_domain","server_port","sub_path"]:
            if key in request.form: ss(key, request.form[key])
        return redirect(url_for("settings_page"))
    return render_template_string(SETTINGS_HTML, version=VERSION, panel_name=gs("panel_title"),
        domain=gs("server_domain"), port=gs("server_port"), sub_path=gs("sub_path"), title=gs("panel_title"))

@app.route("/api/inbound/add", methods=["POST"])
@login_required
def add_inbound():
    d = request.json; u = d.get("uuid") or str(uuid.uuid4())
    db = get_db()
    db.execute("""INSERT INTO inbounds (name,protocol,port,uuid,flow,network,security,sni,domain,host,path,remark,tag)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (d.get("name",""), d.get("protocol","vless"), d.get("port",443), u,
         d.get("flow",""), d.get("network","ws"), d.get("security","none"),
         d.get("sni",""), d.get("domain",""), d.get("host",""),
         d.get("path","/"), d.get("remark",""), d.get("tag","")))
    db.commit(); db.close(); return jsonify({"success":True, "uuid":u})

@app.route("/api/inbound/delete/<int:pid>", methods=["POST"])
@login_required
def del_inbound(pid):
    db = get_db(); db.execute("DELETE FROM inbounds WHERE id=?", (pid,))
    db.execute("DELETE FROM users_vpn WHERE inbound_id=?", (pid,))
    db.commit(); db.close(); return jsonify({"success":True})

@app.route("/api/inbound/toggle/<int:pid>", methods=["POST"])
@login_required
def toggle_inbound(pid):
    db = get_db()
    r = db.execute("SELECT enable FROM inbounds WHERE id=?", (pid,)).fetchone()
    if r: db.execute("UPDATE inbounds SET enable=? WHERE id=?", (0 if r["enable"] else 1, pid))
    db.commit(); db.close(); return jsonify({"success":True})

@app.route("/api/user/add", methods=["POST"])
@login_required
def add_user():
    d = request.json; u = d.get("uuid") or str(uuid.uuid4())
    db = get_db()
    db.execute("""INSERT INTO users_vpn (email,uuid,enable,total,expiry,inbound_id,limit_ip,tg_id,comment)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (d.get("email","user"), u, 1, int(d.get("total",0))*1073741824,
         int(d.get("expiry",30))*86400, int(d.get("inbound_id",0)),
         int(d.get("limit_ip",0)), d.get("tg_id",""), d.get("comment","")))
    db.commit(); db.close(); return jsonify({"success":True, "uuid":u})

@app.route("/api/user/delete/<int:uid>", methods=["POST"])
@login_required
def del_user(uid):
    db = get_db(); db.execute("DELETE FROM users_vpn WHERE id=?", (uid,))
    db.commit(); db.close(); return jsonify({"success":True})

@app.route("/api/user/toggle/<int:uid>", methods=["POST"])
@login_required
def toggle_user(uid):
    db = get_db()
    r = db.execute("SELECT enable FROM users_vpn WHERE id=?", (uid,)).fetchone()
    if r: db.execute("UPDATE users_vpn SET enable=? WHERE id=?", (0 if r["enable"] else 1, uid))
    db.commit(); db.close(); return jsonify({"success":True})

@app.route("/api/user/info/<int:uid>")
@login_required
def user_info(uid):
    db = get_db()
    u = db.execute("""SELECT u.*, i.name as inb_name, i.protocol, i.port as inb_port,
        i.domain, i.sni, i.network, i.security, i.path, i.host
        FROM users_vpn u JOIN inbounds i ON u.inbound_id=i.id WHERE u.id=?""", (uid,)).fetchone()
    db.close()
    if not u: return jsonify({"error":"not found"}), 404
    exp = int(u['expiry']+time.time()) if u['expiry'] else 0
    return jsonify({
        "email":u["email"],"uuid":u["uuid"],"enable":bool(u["enable"]),
        "up":u["up"],"down":u["down"],"total":u["total"],"expiry":exp,
        "protocol":u["protocol"],"domain":u["domain"] or gs("server_domain"),
        "port":u["inb_port"],"sni":u["sni"],
        "created_at":u["created_at"],"last_login":u["last_login"],
        "traffic_up":f"{u['up']/1073741824:.2f} GB","traffic_down":f"{u['down']/1073741824:.2f} GB",
        "traffic_total":f"{u['total']/1073741824:.2f} GB" if u['total'] else "نامحدود",
        "expiry_date":datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M") if exp else "نامحدود"
    })

def build_link(user, inb):
    proto = inb["protocol"]; uuid_val = user["uuid"]
    domain = inb["domain"] or gs("server_domain","your-domain.com")
    port = inb["port"] or int(gs("server_port","443"))
    sni = inb["sni"] or domain; path = inb["path"] or "/"; net = inb["network"] or "ws"
    sec = inb["security"] or "none"; flow = inb["flow"] or ""; email = user["email"]
    if proto == "vless":
        p = f"host={sni}&path={path}&type={net}"
        if sec == "tls": p += f"&security=tls&sni={sni}&fp=chrome"
        if flow: p += f"&flow={flow}"
        return f"vless://{uuid_val}@{domain}:{port}?{p}#{email}"
    elif proto == "vmess":
        obj = {"v":"2","ps":email,"add":domain,"port":str(port),"id":uuid_val,"aid":"0","scy":"auto","net":net,"type":"tcp","host":sni,"path":path,"tls":sec,"sni":sni}
        return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()
    elif proto == "trojan":
        return f"trojan://{uuid_val}@{domain}:{port}?type={net}&host={sni}&path={path}&security=tls&sni={sni}#{email}"
    return f"{proto}://unsupported"

@app.route("/api/link/<int:uid>")
@login_required
def gen_link(uid):
    db = get_db()
    u = db.execute("SELECT * FROM users_vpn WHERE id=?", (uid,)).fetchone()
    if not u: db.close(); return jsonify({"error":"not found"}), 404
    inb = db.execute("SELECT * FROM inbounds WHERE id=?", (u["inbound_id"],)).fetchone()
    db.close()
    if not inb: return jsonify({"error":"inbound not found"}), 404
    return jsonify({"link":build_link(u, inb), "email":u["email"], "uuid":u["uuid"]})

@app.route("/sub/<token>")
def subscription(token):
    db = get_db()
    user = db.execute("SELECT * FROM users_vpn WHERE uuid=? AND enable=1", (token,)).fetchone()
    if not user: db.close(); return "Not Found", 404
    db.execute("UPDATE users_vpn SET last_login=? WHERE id=?", (datetime.now().isoformat(), user["id"]))
    db.commit()
    inbounds = db.execute("SELECT * FROM inbounds WHERE enable=1").fetchall()
    db.close()
    links = [build_link(user, inb) for inb in inbounds if inb["enable"]]
    if not links: return "No active inbounds", 404
    exp = int(user['expiry']+time.time()) if user['expiry'] else 0
    headers = {"Content-Type":"text/plain; charset=utf-8","Content-Disposition":f"attachment; filename={user['email']}_config.txt",
        "Profile-Update-Interval":"12","Profile-Title":gs("panel_title","XBZ PRO"),
        "Subscription-Userinfo":f"upload={user['up']};download={user['down']};total={user['total']};expire={exp}"}
    return Response("\n".join(links), headers=headers)

@app.route("/sub/<token>/info")
def sub_info(token):
    db = get_db()
    user = db.execute("SELECT * FROM users_vpn WHERE uuid=?", (token,)).fetchone()
    db.close()
    if not user: return jsonify({"error":"not found"}), 404
    exp = int(user['expiry']+time.time()) if user['expiry'] else 0
    return jsonify({"email":user["email"],"uuid":user["uuid"],"enable":bool(user["enable"]),
        "up":user["up"],"down":user["down"],"total":user["total"],"expiry":exp})

@app.route("/share/<token>")
def share_page(token):
    db = get_db()
    user = db.execute("""SELECT u.*, i.name as inb_name, i.protocol, i.port as inb_port,
        i.domain, i.sni, i.network, i.security, i.path FROM users_vpn u
        JOIN inbounds i ON u.inbound_id=i.id WHERE u.uuid=?""", (token,)).fetchone()
    if not user: db.close(); return "Not Found", 404
    link = build_link(user, user)
    exp = int(user['expiry']+time.time()) if user['expiry'] else 0
    exp_str = datetime.fromtimestamp(exp).strftime("%Y/%m/%d") if exp else "∞"
    dn = f"{user['down']/1073741824:.2f} GB"; up = f"{user['up']/1073741824:.2f} GB"
    tn = f"{user['total']/1073741824:.2f} GB" if user['total'] else "∞"
    sub_url = f"{request.host_url}sub/{token}"
    import qrcode, io as _io, base64 as _b64
    qr = qrcode.make(link); buf = _io.BytesIO(); qr.save(buf, format='PNG'); buf.seek(0)
    qr_b64 = _b64.b64encode(buf.getvalue()).decode()
    usage_pct = min(100, int((user['up']+user['down'])/user['total']*100)) if user['total'] > 0 else 0
    db.close()
    return render_template_string(SHARE_HTML, link=link, email=user["email"], uuid=user["uuid"],
        protocol=user["protocol"].upper(), exp_str=exp_str, traffic_str=dn, total_str=tn,
        up_str=up, sub_url=sub_url, enable=user["enable"], panel_name=gs("panel_title"),
        usage_pct=usage_pct, total_bytes=user['total'], qr_data=qr_b64)

@app.route("/api/user/batch", methods=["POST"])
@login_required
def batch_add():
    d = request.json; count = min(int(d.get("count",1)),100)
    prefix = d.get("prefix","user"); inbound_id = int(d.get("inbound_id",0))
    expiry = int(d.get("expiry",30))*86400; total = int(d.get("total",0))*1073741824
    db = get_db(); created = []
    for i in range(count):
        u = str(uuid.uuid4()); email = f"{prefix}-{i+1}"
        db.execute("INSERT INTO users_vpn (email,uuid,enable,total,expiry,inbound_id) VALUES (?,?,1,?,?,?)",
                   (email, u, total, expiry, inbound_id))
        created.append({"email":email, "uuid":u})
    db.commit(); db.close(); return jsonify({"success":True, "count":len(created), "users":created})

@app.route("/api/export")
@login_required
def export_data():
    db = get_db()
    inbounds = [dict(r) for r in db.execute("SELECT * FROM inbounds").fetchall()]
    users = [dict(r) for r in db.execute("SELECT * FROM users_vpn").fetchall()]
    settings = {r["key"]:r["value"] for r in db.execute("SELECT * FROM settings").fetchall()}
    db.close()
    return jsonify({"inbounds":inbounds,"users":users,"settings":settings,"version":VERSION})

# ═══════════════════════════════════════════════════════
# MARZBAN-STYLE LIGHT THEME CSS
# ═══════════════════════════════════════════════════════

CSS = """
:root{--bg:#f5f7fa;--white:#fff;--card:#fff;--border:#e8ecf0;--text:#1a1a2e;
--text2:#64748b;--text3:#94a3b8;--blue:#2563eb;--blue2:#3b82f6;
--bluebg:rgba(37,99,235,0.08);--green:#16a34a;--greenbg:rgba(22,163,74,0.08);
--red:#dc2626;--redbg:rgba(220,38,38,0.08);--orange:#ea580c;--purple:#7c3aed;
--shadow:0 1px 3px rgba(0,0,0,0.06);--shadow2:0 4px 16px rgba(0,0,0,0.08);
--r:10px;--r2:14px;--r3:20px;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
a{text-decoration:none;color:var(--blue)}
button{font-family:inherit;cursor:pointer}
input,select,textarea{font-family:inherit}
"""

LOGIN_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>XBZ PRO - Login</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>""" + CSS + """
body{display:flex;align-items:center;justify-content:center;background:var(--bg);min-height:100vh}
.login-card{background:var(--white);border:1px solid var(--border);border-radius:var(--r3);padding:48px 40px;width:420px;max-width:92vw;text-align:center;box-shadow:var(--shadow2)}
.login-icon{width:72px;height:72px;margin:0 auto 20px;background:var(--bluebg);border-radius:18px;display:flex;align-items:center;justify-content:center;font-size:2em}
.login-card h1{color:var(--text);font-size:1.5em;font-weight:700;margin-bottom:6px}
.login-card .sub{color:var(--text2);font-size:0.9em;margin-bottom:32px}
.field{margin-bottom:16px;text-align:right}
.field label{display:block;color:var(--text2);font-size:0.82em;font-weight:600;margin-bottom:6px}
.field input{width:100%;padding:13px 16px;border:1.5px solid var(--border);border-radius:var(--r);background:var(--white);color:var(--text);font-size:0.92em;transition:0.2s}
.field input:focus{border-color:var(--blue);outline:none;box-shadow:0 0 0 3px rgba(37,99,235,0.1)}
.field input::placeholder{color:var(--text3)}
.btn-login{width:100%;padding:14px;background:var(--blue);border:none;border-radius:var(--r);color:#fff;font-size:0.95em;font-weight:700;transition:0.2s;display:flex;align-items:center;justify-content:center;gap:8px}
.btn-login:hover{background:#1d4ed8;box-shadow:0 4px 12px rgba(37,99,235,0.3)}
.err{color:var(--red);margin-bottom:16px;font-size:0.85em;background:var(--redbg);padding:12px;border-radius:var(--r)}
.login-footer{margin-top:24px;color:var(--text3);font-size:0.75em}
</style></head><body>
<div class="login-card">
<div class="login-icon">⚡</div>
<h1>وارد حساب خود شوید</h1>
<div class="sub">خوش آمدید، لطفا اطلاعات خود را وارد کنید</div>
{{% if error %}}<div class="err">{{error}}</div>{{% endif %}}
<form method="POST">
<div class="field"><label>نام کاربری</label><input name="username" placeholder="نام کاربری" required></div>
<div class="field"><label>گذرواژه</label><input name="password" type="password" placeholder="گذرواژه" required></div>
<button type="submit" class="btn-login">🚪 ورود</button>
</form>
<div class="login-footer">XBZ PRO (v""" + VERSION + """), ساخته شده با ❤️</div>
</div></body></html>"""

DASH_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{panel_name}}</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>""" + CSS + """
.topbar{background:var(--white);border-bottom:1px solid var(--border);padding:0 24px;display:flex;justify-content:space-between;align-items:center;height:56px;position:sticky;top:0;z-index:50}
.topbar .brand{display:flex;align-items:center;gap:10px}
.topbar .brand h2{font-size:1.1em;font-weight:700;color:var(--text)}.topbar .brand span{color:var(--blue)}
.topbar .brand .v{color:var(--text3);font-size:0.7em;background:var(--bg);padding:2px 8px;border-radius:10px;border:1px solid var(--border)}
.topbar .links{display:flex;gap:4px}
.topbar .links a{color:var(--text2);padding:8px 12px;border-radius:var(--r);font-size:0.83em;font-weight:600;transition:0.15s}.topbar .links a:hover{background:var(--bg);color:var(--text)}
.ct{max-width:1100px;margin:24px auto;padding:0 20px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:24px}
.stat{background:var(--white);border:1px solid var(--border);border-radius:var(--r2);padding:18px;display:flex;align-items:center;gap:14px}
.stat .ico{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.3em}
.stat .ico.p{background:rgba(124,58,237,0.08);color:var(--purple)}.stat .ico.b{background:var(--bluebg);color:var(--blue)}.stat .ico.g{background:var(--greenbg);color:var(--green)}
.stat .info .n{font-size:1.4em;font-weight:800;color:var(--text)}.stat .info .lb{color:var(--text3);font-size:0.78em;font-weight:600}
.sec{background:var(--white);border:1px solid var(--border);border-radius:var(--r3);padding:20px;margin-bottom:20px}
.sec-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:10px}
.btn{padding:9px 20px;border:none;border-radius:var(--r);font-size:0.85em;font-weight:600;transition:0.15s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:var(--blue);color:#fff}.btn-primary:hover{background:#1d4ed8}
.btn-refresh{background:var(--bg);color:var(--text2);border:1px solid var(--border)}.btn-refresh:hover{background:var(--border)}
.search{flex:1;min-width:200px;position:relative}
.search input{width:100%;padding:10px 16px 10px 40px;border:1.5px solid var(--border);border-radius:var(--r);font-size:0.85em;background:var(--white)}
.search input:focus{border-color:var(--blue);outline:none}
.search::before{content:'🔍';position:absolute;left:14px;top:50%;transform:translateY(-50%);font-size:0.85em}
table{width:100%;border-collapse:collapse}
thead th{padding:10px 14px;text-align:right;font-size:0.75em;font-weight:700;color:var(--text3);border-bottom:2px solid var(--border);text-transform:uppercase;letter-spacing:0.3px}
tbody td{padding:12px 14px;font-size:0.88em;border-bottom:1px solid var(--border)}
tbody tr{transition:0.15s}tbody tr:hover{background:rgba(37,99,235,0.02)}
.badge{display:inline-flex;align-items:center;gap:4px;padding:4px 12px;border-radius:20px;font-size:0.75em;font-weight:600}
.bg{background:var(--greenbg);color:var(--green)}.br{background:var(--redbg);color:var(--red)}.bp{background:var(--bluebg);color:var(--blue)}
.user-name{font-weight:700;color:var(--text)}
.trf{font-size:0.82em;color:var(--text2);direction:ltr}
.prog{height:6px;background:var(--bg);border-radius:3px;overflow:hidden;margin-top:6px;width:120px;display:inline-block}
.prog-fill{height:100%;background:var(--blue);border-radius:3px}
.btn-s{padding:4px 10px;border:none;border-radius:8px;font-size:0.75em;font-weight:600;transition:0.15s;cursor:pointer}
.bs{background:var(--bluebg);color:var(--blue)}.bs:hover{background:rgba(37,99,235,0.15)}
.bw{background:rgba(234,88,12,0.08);color:var(--orange)}.bw:hover{background:rgba(234,88,12,0.15)}
.bd{background:var(--redbg);color:var(--red)}.bd:hover{background:rgba(220,38,38,0.15)}
.bgrp{display:flex;gap:4px}
.mo{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:100;align-items:center;justify-content:center;backdrop-filter:blur(2px)}.mo.show{display:flex}
.md{background:var(--white);border-radius:var(--r3);padding:28px;width:500px;max-width:94vw;max-height:88vh;overflow-y:auto;box-shadow:var(--shadow2)}
.md-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.md-h h3{font-size:1.05em;font-weight:700;display:flex;align-items:center;gap:8px}
.md-x{width:32px;height:32px;border-radius:50%;border:1px solid var(--border);background:var(--white);color:var(--text3);font-size:1em;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:0.15s}.md-x:hover{background:var(--redbg);color:var(--red);border-color:var(--red)}
.field{margin-bottom:14px;text-align:right}.field label{display:block;color:var(--text2);font-size:0.8em;font-weight:600;margin-bottom:5px}
.field input,.field select{width:100%;padding:10px 14px;border:1.5px solid var(--border);border-radius:var(--r);background:var(--white);font-size:0.88em;transition:0.2s}
.field input:focus,.field select:focus{border-color:var(--blue);outline:none}
.fr{display:flex;gap:8px;flex-wrap:wrap}.fr>.field{flex:1;min-width:120px}
.proto-cards{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px}
.proto-card{padding:12px;border:2px solid var(--border);border-radius:var(--r);cursor:pointer;transition:0.15s;text-align:center}
.proto-card:hover{border-color:var(--blue);background:var(--bluebg)}
.proto-card.active{border-color:var(--blue);background:var(--bluebg)}
.proto-card .name{font-weight:700;font-size:0.9em;color:var(--text)}.proto-card .desc{font-size:0.72em;color:var(--text3);margin-top:2px}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--text);color:#fff;padding:12px 24px;border-radius:var(--r);font-size:0.88em;font-weight:600;display:none;z-index:200}
.pagination{display:flex;align-items:center;justify-content:space-between;margin-top:16px;padding-top:14px;border-top:1px solid var(--border);font-size:0.82em;color:var(--text3)}
.uuid{font-family:monospace;font-size:0.72em;color:var(--text3);direction:ltr}
.expand-row{display:none;background:var(--bg);padding:14px;border-radius:var(--r)}
.expand-row.show{display:table-row}
@media(max-width:768px){.stats{grid-template-columns:1fr}.proto-cards{grid-template-columns:1fr}}
</style></head><body>
<div class="topbar"><div class="brand"><h2>⚡ <span>XBZ PRO</span></h2><span class="v">v{{version}}</span></div>
<div class="links"><a href="/settings">⚙️ تنظیمات</a><a href="/api/export" target="_blank">📦 خروجی</a><a href="/logout">🚪 خروج</a></div></div>
<div class="ct">
<div class="stats">
<div class="stat"><div class="ico p">👥</div><div class="info"><div class="n">{{active_users}} / {{total_users}}</div><div class="lb">کاربران فعال</div></div></div>
<div class="stat"><div class="ico b">📊</div><div class="info"><div class="n">{{'%0.2f'|format(total_data/1073741824)}} GB</div><div class="lb">مصرف داده</div></div></div>
<div class="stat"><div class="ico g">📡</div><div class="info"><div class="n">{{total_inbounds}}</div><div class="lb">اینباندها</div></div></div>
</div>

<div class="sec">
<div class="sec-top">
<button class="btn btn-primary" onclick="showM('usM')">➕ افزودن کاربر</button>
<button class="btn btn-refresh" onclick="location.reload()">🔄</button>
<div class="search"><input id="searchInput" placeholder="جستجو" oninput="filterUsers()"></div>
</div>
<table><thead><tr><th>کاربران</th><th>وضعیت</th><th>مصرف داده</th><th>عملیات</th></tr></thead>
<tbody id="userTable">
{% for u in users %}
<tr class="urow" data-name="{{u.email}}">
<td><div class="user-name">{{u.email}}</div><div class="uuid">{{u.uuid[:16]}}...</div></td>
<td>{% if u.enable %}<span class="badge bg">🟢 فعال</span>{% else %}<span class="badge br">🔴 غیرفعال</span>{% endif %}</td>
<td><span class="trf">{{'%0.2f'|format((u.up+u.down)/1073741824)}} / {% if u.total %}{{'%0.2f'|format(u.total/1073741824)}} GB{% else %}∞{% endif %}</span>
{% if u.total %}<div class="prog"><div class="prog-fill" style="width:{{[100, ((u.up+u.down)*100//u.total)|int] | min}}%"></div></div>{% endif %}</td>
<td><div class="bgrp">
<button class="btn-s bs" onclick="getL({{u.id}})" title="لینک">🔗</button>
<button class="btn-s bs" onclick="shareP('{{u.uuid}}')" title="صفحه">👁️</button>
<button class="btn-s bw" onclick="togU({{u.id}})" title="تغییر وضعیت">🔄</button>
<button class="btn-s bd" onclick="delU({{u.id}})" title="حذف">🗑️</button>
</div></td></tr>
{% endfor %}
</tbody></table>
<div class="pagination"><span>{{total_users}} کاربر</span><span>صفحه 1</span></div>
</div>

<div class="sec">
<div class="sec-top"><h3 style="font-size:1em;font-weight:700">📡 اینباندها</h3>
<button class="btn btn-primary" onclick="showM('inM')">➕ ایجاد جدید</button></div>
<table><thead><tr><th>#</th><th>نام</th><th>پروتکل</th><th>پورت</th><th>Domain</th><th>SNI</th><th>وضعیت</th><th>عملیات</th></tr></thead>
<tbody>{% for i in inbounds %}<tr>
<td>{{i.id}}</td><td class="user-name">{{i.name}}</td>
<td><span class="badge bp">{{i.protocol|upper}}</span></td>
<td>{{i.port}}</td><td style="font-size:0.8em">{{i.domain}}</td><td style="font-size:0.8em">{{i.sni}}</td>
<td>{% if i.enable %}<span class="badge bg">فعال</span>{% else %}<span class="badge br">غیرفعال</span>{% endif %}</td>
<td><div class="bgrp"><button class="btn-s bw" onclick="togIn({{i.id}})">🔄</button><button class="btn-s bd" onclick="delIn({{i.id}})">🗑️</button></div></td></tr>{% endfor %}</tbody></table>
</div></div>

<div class="mo" id="usM"><div class="md"><div class="md-h"><h3>👤 ساخت کاربر</h3><button class="md-x" onclick="hideM('usM')">✕</button></div>
<div class="field"><label>نام کاربری</label><input id="u-e" placeholder="نام کاربری"></div>
<div class="field"><label>پروتکل</label><select id="u-proto" style="width:100%;padding:10px 14px;border:1.5px solid var(--border);border-radius:var(--r);font-size:0.88em">{% for i in inbounds %}<option value="{{i.id}}">{{i.name}} ({{i.protocol|upper}}:{{i.port}})</option>{% endfor %}</select></div>
<div class="fr"><div class="field"><label>حد مصرف (GB)</label><input id="u-t" type="number" value="5"></div>
<div class="field"><label>تاریخ پایان (روز)</label><input id="u-ex" type="number" value="30"></div></div>
<div class="field"><label>محدودیت IP</label><input id="u-li" type="number" value="0" placeholder="0 = نامحدود"></div>
<div class="field"><label>توضیحات</label><input id="u-cm" placeholder="توضیحات اختیاری"></div>
<button class="btn btn-primary" onclick="addU()" style="width:100%">افزودن کاربر</button></div></div>

<div class="mo" id="inM"><div class="md"><div class="md-h"><h3>📡 ایجاد اینباند</h3><button class="md-x" onclick="hideM('inM')">✕</button></div>
<div class="field"><label>نام</label><input id="i-n" placeholder="نام اینباند" value="VLESS-NL"></div>
<div class="fr"><div class="field"><label>پورت</label><input id="i-pt" type="number" value="443"></div>
<div class="field"><label>شبکه</label><select id="i-nw"><option value="ws">WebSocket</option><option value="grpc">gRPC</option><option value="tcp">TCP</option></select></div></div>
<div class="fr"><div class="field"><label>Domain</label><input id="i-d" placeholder="دامنه"></div>
<div class="field"><label>SNI</label><input id="i-s" placeholder="SNI"></div></div>
<div class="fr"><div class="field"><label>Host</label><input id="i-h" placeholder="Host"></div>
<div class="field"><label>Path</label><input id="i-pa" value="/ws"></div></div>
<div class="proto-cards">
<div class="proto-card active" onclick="selProto(this,'vless')"><div class="name">VLESS</div><div class="desc">سریع، سبک و امن</div></div>
<div class="proto-card" onclick="selProto(this,'vmess')"><div class="name">VMess</div><div class="desc">سریع و امن</div></div>
<div class="proto-card" onclick="selProto(this,'trojan')"><div class="name">Trojan</div><div class="desc">امن و فراتر از سرعت</div></div>
<div class="proto-card" onclick="selProto(this,'shadowsocks')"><div class="name">Shadowsocks</div><div class="desc">سریع و ساده</div></div>
</div>
<input type="hidden" id="i-proto" value="vless">
<button class="btn btn-primary" onclick="addIn()" style="width:100%">افزودن اینباند</button></div></div>

<div class="toast" id="t">✅ انجام شد!</div>
<script>
function showM(id){document.getElementById(id).classList.add('show')}
function hideM(id){document.getElementById(id).classList.remove('show')}
function g(id){return document.getElementById(id).value}
function toast(){var e=document.getElementById('t');e.style.display='block';setTimeout(()=>e.style.display='none',2000)}
function selProto(el,p){document.querySelectorAll('.proto-card').forEach(c=>c.classList.remove('active'));el.classList.add('active');document.getElementById('i-proto').value=p}
function filterUsers(){var q=document.getElementById('searchInput').value.toLowerCase();document.querySelectorAll('.urow').forEach(r=>{r.style.display=r.dataset.name.toLowerCase().includes(q)?'':'none'})}
function addIn(){fetch("/api/inbound/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:g("i-n"),protocol:g("i-proto"),port:g("i-pt"),domain:g("i-d"),sni:g("i-s"),host:g("i-h"),path:g("i-pa"),network:g("i-nw")})}).then(r=>r.json()).then(d=>{if(d.success)location.reload()})}
function delIn(id){if(confirm("حذف شود؟"))fetch("/api/inbound/delete/"+id,{method:"POST"}).then(()=>location.reload())}
function togIn(id){fetch("/api/inbound/toggle/"+id,{method:"POST"}).then(()=>location.reload())}
function addU(){fetch("/api/user/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:g("u-e"),inbound_id:g("u-proto"),expiry:g("u-ex"),total:g("u-t"),limit_ip:g("u-li"),comment:g("u-cm")})}).then(r=>r.json()).then(d=>{if(d.success){navigator.clipboard.writeText(location.origin+"/sub/"+d.uuid);toast();setTimeout(()=>location.reload(),1000)}})}
function delU(id){if(confirm("حذف شود؟"))fetch("/api/user/delete/"+id,{method:"POST"}).then(()=>location.reload())}
function togU(id){fetch("/api/user/toggle/"+id,{method:"POST"}).then(()=>location.reload())}
function getL(id){fetch("/api/link/"+id).then(r=>r.json()).then(d=>{navigator.clipboard.writeText(d.link).then(()=>toast())})}
function shareP(uuid){window.open("/share/"+uuid,"_blank")}
</script></body></html>"""

SETTINGS_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Settings</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>""" + CSS + """
.topbar{background:var(--white);border-bottom:1px solid var(--border);padding:0 24px;display:flex;justify-content:space-between;align-items:center;height:56px}
.topbar .brand{display:flex;align-items:center;gap:10px}.topbar .brand h2{font-size:1.1em;font-weight:700}.topbar .brand span{color:var(--blue)}
.topbar .links{display:flex;gap:4px}.topbar .links a{color:var(--text2);padding:8px 12px;border-radius:var(--r);font-size:0.83em;font-weight:600;transition:0.15s}.topbar .links a:hover{background:var(--bg);color:var(--text)}
.ct{max-width:600px;margin:36px auto;padding:0 20px}
.card{background:var(--white);border:1px solid var(--border);border-radius:var(--r3);padding:28px}
.card h3{font-size:1.05em;font-weight:700;margin-bottom:20px}
.field{margin-bottom:14px;text-align:right}.field label{display:block;color:var(--text2);font-size:0.8em;font-weight:600;margin-bottom:5px}
.field input{width:100%;padding:10px 14px;border:1.5px solid var(--border);border-radius:var(--r);font-size:0.88em}
.field input:focus{border-color:var(--blue);outline:none}
.btn{width:100%;padding:14px;background:var(--blue);border:none;border-radius:var(--r);color:#fff;font-size:0.92em;font-weight:700;transition:0.15s}
.btn:hover{background:#1d4ed8}
.info{background:var(--bg);border:1px solid var(--border);border-radius:var(--r2);padding:18px;margin-top:18px;font-size:0.82em;color:var(--text2);line-height:2.2}
.info strong{color:var(--blue)}.info code{color:var(--blue);background:var(--bluebg);padding:3px 8px;border-radius:6px;font-size:0.9em}
</style></head><body>
<div class="topbar"><div class="brand"><h2>⚡ <span>XBZ PRO</span></h2><span class="v" style="color:var(--text3);font-size:0.7em;background:var(--bg);padding:2px 8px;border-radius:10px;border:1px solid var(--border)">v""" + VERSION + """</span></div>
<div class="links"><a href="/">🏠 داشبورد</a><a href="/logout">🚪 خروج</a></div></div>
<div class="ct"><div class="card"><h3>⚙️ تنظیمات پنل</h3>
<form method="POST"><div class="field"><label>نام پنل</label><input name="panel_title" value="{{title}}"></div>
<div class="field"><label>دامنه سرور</label><input name="server_domain" value="{{domain}}"></div>
<div class="field"><label>پورت سرور</label><input name="server_port" value="{{port}}"></div>
<div class="field"><label>مسیر اشتراک</label><input name="sub_path" value="{{sub_path}}"></div>
<button type="submit" class="btn">💾 ذخیره تنظیمات</button></form>
<div class="info"><strong>📌 آدرس‌ها:</strong><br>ساب: <code>{{domain}}:{{port}}{{sub_path}}/{{UUID}}</code><br>صفحه: <code>{{domain}}:{{port}}/share/{{UUID}}</code><br>سازگار: v2rayNG · Hiddify · Nekobox · V2Box · Streisand</div></div></div></body></html>"""

SHARE_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{email}}</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>""" + CSS + """
.page{max-width:480px;margin:0 auto;padding:20px 16px}
.hdr{text-align:center;margin-bottom:20px}.hdr .ic{font-size:2.5em}.hdr h1{font-size:1.4em;font-weight:800;margin:6px 0 2px}.hdr .s{color:var(--text3);font-size:0.85em}
.card{background:var(--white);border:1px solid var(--border);border-radius:var(--r2);padding:18px;margin-bottom:12px}
.row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border)}.row:last-child{border:none}
.row .l{color:var(--text3);font-size:0.8em;font-weight:600}.row .v{color:var(--text);font-size:0.85em;font-weight:700;text-align:left}
.badge{display:inline-flex;padding:4px 12px;border-radius:20px;font-size:0.75em;font-weight:600}.bg{background:var(--greenbg);color:var(--green)}.bp{background:var(--bluebg);color:var(--blue)}
.usage{height:8px;background:var(--bg);border-radius:4px;overflow:hidden;margin:10px 0}.fill{height:100%;background:var(--blue);border-radius:4px}
.sub-card{background:var(--white);border:1px solid var(--border);border-radius:var(--r2);padding:18px;margin-bottom:12px}
.sub-card h3{font-size:0.92em;font-weight:700;margin-bottom:12px}
.srow{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)}.srow:last-child{border:none}
.srow .inf{flex:1;min-width:0}.srow .lb{color:var(--text3);font-size:0.72em;font-weight:600;margin-bottom:2px}.srow .vl{font-size:0.75em;color:var(--text2);font-family:monospace;direction:ltr;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.srow .act{display:flex;gap:6px;margin-right:10px}
.ab{width:34px;height:34px;border-radius:9px;border:none;display:flex;align-items:center;justify-content:center;font-size:0.95em;transition:0.15s;cursor:pointer}
.ac{background:var(--bluebg);color:var(--blue)}.ac:hover{background:rgba(37,99,235,0.15)}
.aq{background:rgba(124,58,237,0.08);color:var(--purple)}.aq:hover{background:rgba(124,58,237,0.15)}
.cpy{width:100%;padding:14px;background:var(--blue);border:none;border-radius:var(--r);color:#fff;font-size:0.92em;font-weight:700;cursor:pointer;transition:0.15s}
.cpy:hover{background:#1d4ed8}
.qr{text-align:center;padding:16px;display:none}.qr img{border-radius:var(--r2);border:2px solid var(--border)}
.pbtns{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}
.pbtn{padding:14px;border:none;border-radius:var(--r);font-size:0.88em;font-weight:700;cursor:pointer;transition:0.15s;display:flex;align-items:center;justify-content:center;gap:6px}
.pa{background:var(--bluebg);color:var(--blue);border:1px solid rgba(37,99,235,0.15)}.pa:hover{background:rgba(37,99,235,0.12)}
.pi{background:rgba(124,58,237,0.08);color:var(--purple);border:1px solid rgba(124,58,237,0.15)}.pi:hover{background:rgba(124,58,237,0.12)}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--text);color:#fff;padding:12px 24px;border-radius:var(--r);font-size:0.88em;display:none;z-index:100}
</style></head><body>
<div class="page">
<div class="hdr"><div class="ic">⚡</div><h1>{{panel_name}}</h1><div class="s">{{email}}</div></div>
<div class="card">
<div class="row"><span class="l">شناسه</span><span class="v" style="font-size:0.7em;font-family:monospace;direction:ltr">{{uuid}}</span></div>
<div class="row"><span class="l">وضعیت</span><span class="v">{% if enable %}<span class="badge bg">🟢 فعال</span>{% else %}<span class="badge br">🔴 غیرفعال</span>{% endif %}</span></div>
<div class="row"><span class="l">پروتکل</span><span class="v"><span class="badge bp">{{protocol}}</span></span></div>
<div class="row"><span class="l">دانلود</span><span class="v">{{traffic_str}}</span></div>
<div class="row"><span class="l">آپلود</span><span class="v">{{up_str}}</span></div>
<div class="row"><span class="l">حجم کل</span><span class="v">{{total_str}}</span></div>
<div class="row"><span class="l">انقضا</span><span class="v">{{exp_str}}</span></div>
</div>
<div class="card"><div style="display:flex;justify-content:space-between;font-size:0.8em;color:var(--text3)"><span>{{traffic_str}} / {{total_str}}</span><span class="badge bp">⚡ {% if total_bytes > 0 %}{{usage_pct}}%{% else %}∞{% endif %}</span></div>
<div class="usage"><div class="fill" style="width:{{usage_pct}}%"></div></div></div>
<div class="sub-card"><h3>🔗 اطلاعات اشتراک</h3>
<div class="srow"><div class="inf"><div class="lb">لینک اشتراک</div><div class="vl">{{sub_url}}</div></div><div class="act"><button class="ab ac" onclick="cT('{{sub_url}}')">📋</button><button class="ab aq" onclick="sQR()">📱</button></div></div>
<div class="srow"><div class="inf"><div class="lb">لینک VPN</div><div class="vl">{{link}}</div></div><div class="act"><button class="ab ac" onclick="cT('{{link}}')">📋</button></div></div></div>
<button class="cpy" onclick="cT('{{link}}')">📋 کپی لینک VPN</button>
<div class="qr" id="qrBox"><img src="data:image/png;base64,{{qr_data}}" width="200"></div>
<div class="pbtns"><button class="pbtn pa" onclick="cT('{{sub_url}}')">🤖 Android</button><button class="pbtn pi" onclick="cT('{{sub_url}}')">🍎 iOS</button></div>
</div><div class="toast" id="t">✅ کپی شد!</div>
<script>function cT(t){navigator.clipboard.writeText(t).then(()=>{var e=document.getElementById('t');e.style.display='block';setTimeout(()=>e.style.display='none',2000)})}function sQR(){var b=document.getElementById('qrBox');b.style.display=b.style.display==='block'?'none':'block'}</script></body></html>"""

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)
