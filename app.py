import os, json, uuid, sqlite3, secrets, base64, time
from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify, Response
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_USER = os.environ.get("ADMIN_USER", "xbz")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "xbz2026")
DB = "xbz.db"
VERSION = "1.6.0"

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
    db = get_db()
    r = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    db.close(); return r["value"] if r else default

def ss(key, value):
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, value))
    db.commit(); db.close()

def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get("logged_in"): return redirect(url_for("login"))
        return f(*a, **kw)
    return d

# ─── Auth ───────────────────────────────────────────────
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

# ─── Dashboard ──────────────────────────────────────────
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
    tup = sum(u["up"] for u in users); tdn = sum(u["down"] for u in users)
    ti = len(inbounds)
    now = time.time()
    expired = sum(1 for u in users if u["expiry"] and u["expiry"] < now)
    db.close()
    return render_template_string(DASH_HTML, inbounds=inbounds, users=users,
        total_users=tu, active_users=au, expired_users=expired, total_up=tup,
        total_down=tdn, total_inbounds=ti, version=VERSION, panel_name=gs("panel_title"))

@app.route("/settings", methods=["GET","POST"])
@login_required
def settings_page():
    if request.method == "POST":
        for key in ["panel_title","server_domain","server_port","sub_path"]:
            if key in request.form: ss(key, request.form[key])
        return redirect(url_for("settings_page"))
    return render_template_string(SETTINGS_HTML, version=VERSION,
        panel_name=gs("panel_title"), domain=gs("server_domain"),
        port=gs("server_port"), sub_path=gs("sub_path"), title=gs("panel_title"))

# ─── API: Inbounds ──────────────────────────────────────
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
    db.commit(); db.close()
    return jsonify({"success":True, "uuid":u})

@app.route("/api/inbound/delete/<int:pid>", methods=["POST"])
@login_required
def del_inbound(pid):
    db = get_db()
    db.execute("DELETE FROM inbounds WHERE id=?", (pid,))
    db.execute("DELETE FROM users_vpn WHERE inbound_id=?", (pid,))
    db.commit(); db.close()
    return jsonify({"success":True})

@app.route("/api/inbound/toggle/<int:pid>", methods=["POST"])
@login_required
def toggle_inbound(pid):
    db = get_db()
    r = db.execute("SELECT enable FROM inbounds WHERE id=?", (pid,)).fetchone()
    if r: db.execute("UPDATE inbounds SET enable=? WHERE id=?", (0 if r["enable"] else 1, pid))
    db.commit(); db.close()
    return jsonify({"success":True})

# ─── API: Users ─────────────────────────────────────────
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
    db.commit(); db.close()
    return jsonify({"success":True, "uuid":u})

@app.route("/api/user/delete/<int:uid>", methods=["POST"])
@login_required
def del_user(uid):
    db = get_db(); db.execute("DELETE FROM users_vpn WHERE id=?", (uid,))
    db.commit(); db.close()
    return jsonify({"success":True})

@app.route("/api/user/toggle/<int:uid>", methods=["POST"])
@login_required
def toggle_user(uid):
    db = get_db()
    r = db.execute("SELECT enable FROM users_vpn WHERE id=?", (uid,)).fetchone()
    if r: db.execute("UPDATE users_vpn SET enable=? WHERE id=?", (0 if r["enable"] else 1, uid))
    db.commit(); db.close()
    return jsonify({"success":True})

@app.route("/api/user/reset/<int:uid>", methods=["POST"])
@login_required
def reset_user(uid):
    db = get_db(); db.execute("UPDATE users_vpn SET up=0, down=0 WHERE id=?", (uid,))
    db.commit(); db.close()
    return jsonify({"success":True})

@app.route("/api/user/info/<int:uid>")
@login_required
def user_info(uid):
    db = get_db()
    u = db.execute("""SELECT u.*, i.name as inb_name, i.protocol, i.port as inb_port,
        i.domain, i.sni, i.network, i.security, i.path, i.host, i.flow
        FROM users_vpn u JOIN inbounds i ON u.inbound_id=i.id WHERE u.id=?""", (uid,)).fetchone()
    db.close()
    if not u: return jsonify({"error":"not found"}), 404
    exp = int(u['expiry']+time.time()) if u['expiry'] else 0
    domain = u["domain"] or gs("server_domain")
    return jsonify({
        "email":u["email"],"uuid":u["uuid"],"enable":bool(u["enable"]),
        "up":u["up"],"down":u["down"],"total":u["total"],"expiry":exp,
        "limit_ip":u["limit_ip"],"protocol":u["protocol"],
        "domain":domain,"port":u["inb_port"],"sni":u["sni"],
        "created_at":u["created_at"],"last_login":u["last_login"],
        "traffic_up":f"{u['up']/1073741824:.2f} GB",
        "traffic_down":f"{u['down']/1073741824:.2f} GB",
        "traffic_total":f"{u['total']/1073741824:.2f} GB" if u['total'] else "Unlimited",
        "expiry_date":datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M") if exp else "Never"
    })

# ─── Link Builder ───────────────────────────────────────
def build_link(user, inb):
    proto = inb["protocol"]; uuid_val = user["uuid"]
    domain = inb["domain"] or gs("server_domain","your-domain.com")
    port = inb["port"] or int(gs("server_port","443"))
    sni = inb["sni"] or domain; host = inb["host"] or domain
    path = inb["path"] or "/"; net = inb["network"] or "ws"
    sec = inb["security"] or "none"; flow = inb["flow"] or ""
    email = user["email"]
    if proto == "vless":
        p = f"host={sni}&path={path}&type={net}"
        if sec == "tls": p += f"&security=tls&sni={sni}&fp=chrome&alpn=h2"
        if flow: p += f"&flow={flow}"
        return f"vless://{uuid_val}@{domain}:{port}?{p}#{email}"
    elif proto == "vmess":
        obj = {"v":"2","ps":email,"add":domain,"port":str(port),"id":uuid_val,
               "aid":"0","scy":"auto","net":net,"type":"tcp","host":sni,"path":path,"tls":sec,"sni":sni}
        return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()
    elif proto == "trojan":
        return f"trojan://{uuid_val}@{domain}:{port}?type={net}&host={sni}&path={path}&security=tls&sni={sni}#{email}"
    elif proto == "shadowsocks":
        return f"ss://{base64.b64encode(f'chacha20-ietf-poly1305:{uuid_val}'.encode()).decode()}@{domain}:{port}#{email}"
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

# ─── Subscription ───────────────────────────────────────
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
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f"attachment; filename={user['email']}_config.txt",
        "Profile-Update-Interval": "12",
        "Profile-Title": gs("panel_title","XBZ PRO"),
        "Subscription-Userinfo": f"upload={user['up']};download={user['down']};total={user['total']};expire={exp}"
    }
    return Response("\n".join(links), headers=headers)

@app.route("/sub/<token>/info")
def sub_info(token):
    db = get_db()
    user = db.execute("SELECT * FROM users_vpn WHERE uuid=?", (token,)).fetchone()
    db.close()
    if not user: return jsonify({"error":"not found"}), 404
    exp = int(user['expiry']+time.time()) if user['expiry'] else 0
    return jsonify({
        "email":user["email"],"uuid":user["uuid"],"enable":bool(user["enable"]),
        "up":user["up"],"down":user["down"],"total":user["total"],"expiry":exp,
        "limit_ip":user["limit_ip"],"created_at":user["created_at"],"last_login":user["last_login"]
    })

# ─── Share Page (Marzban Style) ─────────────────────────
@app.route("/share/<token>")
def share_page(token):
    db = get_db()
    user = db.execute("""SELECT u.*, i.name as inb_name, i.protocol, i.port as inb_port,
        i.domain, i.sni, i.network, i.security, i.path, i.host, i.flow
        FROM users_vpn u JOIN inbounds i ON u.inbound_id=i.id WHERE u.uuid=?""", (token,)).fetchone()
    if not user: db.close(); return "Not Found", 404
    link = build_link(user, user)
    exp = int(user['expiry']+time.time()) if user['expiry'] else 0
    exp_str = datetime.fromtimestamp(exp).strftime("%Y/%m/%d") if exp else "∞"
    dn = f"{user['down']/1073741824:.2f} GB"
    up = f"{user['up']/1073741824:.2f} GB"
    tn = f"{user['total']/1073741824:.2f} GB" if user['total'] else "∞"
    sub_url = f"{request.host_url}sub/{token}"
    info_url = f"{request.host_url}sub/{token}/info"
    import qrcode, io as _io, base64 as _b64
    qr = qrcode.make(link)
    buf = _io.BytesIO(); qr.save(buf, format='PNG'); buf.seek(0)
    qr_b64 = _b64.b64encode(buf.getvalue()).decode()
    usage_pct = 0
    if user['total'] > 0:
        usage_pct = min(100, int((user['up']+user['down'])/user['total']*100))
    db.close()
    return render_template_string(SHARE_HTML, link=link, email=user["email"],
        uuid=user["uuid"], protocol=user["protocol"].upper(),
        domain=user["domain"], port=user["port"], qr_data=qr_b64,
        exp_str=exp_str, traffic_str=dn, total_str=tn, up_str=up,
        sub_url=sub_url, info_url=info_url, enable=user["enable"],
        panel_name=gs("panel_title"), usage_pct=usage_pct,
        dn_bytes=user['down'], up_bytes=user['up'], total_bytes=user['total'])

# ─── Batch ──────────────────────────────────────────────
@app.route("/api/user/batch", methods=["POST"])
@login_required
def batch_add():
    d = request.json; count = int(d.get("count", 1))
    prefix = d.get("prefix", "user")
    inbound_id = int(d.get("inbound_id", 0))
    expiry = int(d.get("expiry", 30)) * 86400
    total = int(d.get("total", 0)) * 1073741824
    db = get_db()
    created = []
    for i in range(min(count, 100)):
        u = str(uuid.uuid4())
        email = f"{prefix}-{i+1}"
        db.execute("""INSERT INTO users_vpn (email,uuid,enable,total,expiry,inbound_id)
            VALUES (?,?,1,?,?,?)""", (email, u, total, expiry, inbound_id))
        created.append({"email":email, "uuid":u})
    db.commit(); db.close()
    return jsonify({"success":True, "count":len(created), "users":created})

@app.route("/api/export")
@login_required
def export_data():
    db = get_db()
    inbounds = [dict(r) for r in db.execute("SELECT * FROM inbounds").fetchall()]
    users = [dict(r) for r in db.execute("SELECT * FROM users_vpn").fetchall()]
    settings = {r["key"]:r["value"] for r in db.execute("SELECT * FROM settings").fetchall()}
    db.close()
    return jsonify({"inbounds":inbounds,"users":users,"settings":settings,"version":VERSION})

# ═══════════════════════════════════════════════════════════
# ═══════ HTML TEMPLATES (Marzban Style) ═══════════════════
# ═══════════════════════════════════════════════════════════

COMMON_CSS = """
:root{--bg:#181825;--bg2:#11111b;--card:#1e1e2e;--card2:#252536;
--border:rgba(255,255,255,0.06);--border2:rgba(255,255,255,0.1);
--text:#cdd6f4;--text2:#a6adc8;--text3:#6c7086;
--purple:#cba6f7;--purple2:#b4befe;--pink:#f5c2e7;--pink2:#f38ba8;
--green:#a6e3a1;--green2:#94e2d5;--red:#f38ba8;--orange:#fab387;
--blue:#89b4fa;--cyan:#94e2d5;--yellow:#f9e2af;--mauve:#cba6f7;
--overlay:rgba(0,0,0,0.6);--radius:12px;--radius2:16px;--radius3:20px;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--text3);border-radius:3px}
a{color:var(--purple);text-decoration:none;transition:0.2s}a:hover{color:var(--pink)}
button{font-family:inherit;cursor:pointer}
input,select{font-family:inherit}
"""

LOGIN_CSS = COMMON_CSS + """
body{display:flex;align-items:center;justify-content:center;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 30% 20%,rgba(203,166,247,0.08),transparent 60%),radial-gradient(ellipse at 70% 80%,rgba(245,194,231,0.05),transparent 60%)}
.login-card{position:relative;z-index:1;background:var(--card);border:1px solid var(--border);border-radius:var(--radius3);padding:48px 40px;width:420px;text-align:center;backdrop-filter:blur(20px)}
.login-card .icon{font-size:4em;margin-bottom:12px}
.login-card h1{color:var(--text);font-size:2em;margin-bottom:4px;font-weight:800}
.login-card .ver{color:var(--mauve);font-size:0.82em;font-weight:700;margin-bottom:4px}
.login-card .sub{color:var(--text3);font-size:0.9em;margin-bottom:36px}
.field{margin-bottom:16px;text-align:right}
.field label{display:block;color:var(--text2);font-size:0.82em;margin-bottom:8px;font-weight:600}
.field input{width:100%;padding:14px 18px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg2);color:var(--text);font-size:0.95em;transition:0.3s}
.field input:focus{border-color:var(--mauve);outline:none;box-shadow:0 0 0 3px rgba(203,166,247,0.1)}
.field input::placeholder{color:var(--text3)}
.btn-login{width:100%;padding:15px;background:linear-gradient(135deg,var(--mauve),var(--pink));border:none;border-radius:var(--radius);color:var(--bg);font-size:1em;font-weight:700;transition:0.3s;margin-top:8px}
.btn-login:hover{transform:translateY(-2px);box-shadow:0 8px 25px rgba(203,166,247,0.25)}
.err{color:var(--red);margin-bottom:16px;font-size:0.85em;background:rgba(243,139,168,0.1);padding:10px;border-radius:var(--radius);border:1px solid rgba(243,139,168,0.2)}
"""

DASH_CSS = COMMON_CSS + """
.nav{background:var(--bg2);padding:0 32px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);height:60px}
.nav-brand{display:flex;align-items:center;gap:10px}
.nav-brand h2{color:var(--text);font-size:1.2em;font-weight:800}
.nav-brand h2 span{color:var(--mauve)}
.nav-brand .v{color:var(--text3);font-size:0.7em;font-weight:600;background:var(--card);padding:3px 10px;border-radius:20px;border:1px solid var(--border)}
.nav-links{display:flex;gap:8px;align-items:center}
.nav-links a{color:var(--text3);padding:8px 16px;border-radius:var(--radius);font-size:0.85em;font-weight:600;transition:0.2s;display:flex;align-items:center;gap:6px}
.nav-links a:hover{background:var(--card);color:var(--text)}
.nav-links .btn-logout{color:var(--red)}
.nav-links .btn-logout:hover{background:rgba(243,139,168,0.1);color:var(--red)}
.ct{max-width:1280px;margin:28px auto;padding:0 28px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:28px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:var(--radius2);padding:20px;position:relative;overflow:hidden}
.stat::after{content:'';position:absolute;top:0;right:0;width:4px;height:100%;border-radius:0 4px 4px 0}
.stat.purple::after{background:var(--mauve)}.stat.green::after{background:var(--green)}
.stat.orange::after{background:var(--orange)}.stat.red::after{background:var(--red)}
.stat.blue::after{background:var(--blue)}
.stat .num{font-size:2em;font-weight:800;margin-bottom:4px}
.stat.purple .num{color:var(--mauve)}.stat.green .num{color:var(--green)}
.stat.orange .num{color:var(--orange)}.stat.red .num{color:var(--red)}
.stat.blue .num{color:var(--blue)}
.stat .label{color:var(--text3);font-size:0.8em;font-weight:600}
.sec{background:var(--card);border:1px solid var(--border);border-radius:var(--radius3);padding:24px;margin-bottom:24px}
.sec-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.sec-header h3{color:var(--text);font-size:1.1em;font-weight:700;display:flex;align-items:center;gap:8px}
.sec-header h3 .emoji{font-size:1.2em}
table{width:100%;border-collapse:separate;border-spacing:0}
thead th{padding:12px 14px;text-align:right;font-size:0.72em;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;border-bottom:2px solid var(--border);background:var(--bg2);position:sticky;top:0}
thead th:first-child{border-radius:var(--radius) 0 0 0}thead th:last-child{border-radius:0 var(--radius) 0 0}
tbody td{padding:12px 14px;font-size:0.85em;border-bottom:1px solid var(--border);transition:0.2s}
tbody tr:hover{background:rgba(203,166,247,0.03)}
.badge{display:inline-flex;align-items:center;gap:4px;padding:4px 12px;border-radius:20px;font-size:0.75em;font-weight:600}
.bg{background:rgba(166,227,161,0.12);color:var(--green)}.br{background:rgba(243,139,168,0.12);color:var(--red)}
.bp{background:rgba(203,166,247,0.12);color:var(--mauve)}.bb{background:rgba(137,180,250,0.12);color:var(--blue)}
.bo{background:rgba(250,179,135,0.12);color:var(--orange)}
.btn{padding:6px 14px;border:none;border-radius:8px;font-size:0.78em;font-weight:600;transition:0.2s;display:inline-flex;align-items:center;gap:4px}
.btn-primary{background:linear-gradient(135deg,var(--mauve),var(--pink));color:var(--bg)}
.btn-primary:hover{opacity:0.85;transform:translateY(-1px)}
.btn-info{background:rgba(137,180,250,0.12);color:var(--blue)}.btn-info:hover{background:rgba(137,180,250,0.25)}
.btn-purple{background:rgba(203,166,247,0.12);color:var(--mauve)}.btn-purple:hover{background:rgba(203,166,247,0.25)}
.btn-cyan{background:rgba(148,226,213,0.12);color:var(--cyan)}.btn-cyan:hover{background:rgba(148,226,213,0.25)}
.btn-warning{background:rgba(250,179,135,0.12);color:var(--orange)}.btn-warning:hover{background:rgba(250,179,135,0.25)}
.btn-danger{background:rgba(243,139,168,0.12);color:var(--red)}.btn-danger:hover{background:rgba(243,139,168,0.25)}
.btn-success{background:rgba(166,227,161,0.12);color:var(--green)}.btn-success:hover{background:rgba(166,227,161,0.25)}
.btn-group{display:flex;gap:4px;flex-wrap:nowrap}
.uuid-text{font-family:'Fira Code',monospace;font-size:0.75em;color:var(--text3);direction:ltr}
.traffic{font-size:0.78em;color:var(--text2);direction:ltr;text-align:left}
input,select{padding:10px 14px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg2);color:var(--text);font-size:0.85em;transition:0.2s}
input:focus,select:focus{border-color:var(--mauve);outline:none;box-shadow:0 0 0 3px rgba(203,166,247,0.1)}
select option{background:var(--bg2);color:var(--text)}
.fr{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.cb{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius2);padding:16px;margin-top:14px;word-break:break-all;font-family:'Fira Code',monospace;font-size:0.8em;color:var(--green);display:none;line-height:1.6}
.mo{display:none;position:fixed;inset:0;background:var(--overlay);z-index:100;align-items:center;justify-content:center;backdrop-filter:blur(4px)}
.mo.show{display:flex}
.md{background:var(--card);border:1px solid var(--border2);border-radius:var(--radius3);padding:32px;width:540px;max-height:85vh;overflow-y:auto;box-shadow:0 25px 50px rgba(0,0,0,0.3)}
.md-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}
.md-header h3{color:var(--text);font-size:1.1em;font-weight:700}
.md-close{width:36px;height:36px;border-radius:50%;border:none;background:var(--bg2);color:var(--text3);font-size:1.2em;display:flex;align-items:center;justify-content:center;transition:0.2s}
.md-close:hover{background:rgba(243,139,168,0.15);color:var(--red)}
.toast{position:fixed;bottom:32px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,var(--mauve),var(--pink));color:var(--bg);padding:14px 28px;border-radius:var(--radius);font-size:0.9em;font-weight:600;display:none;z-index:200;box-shadow:0 8px 30px rgba(203,166,247,0.3)}
.info-panel{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius2);padding:20px;margin-top:14px;display:none;font-size:0.85em;line-height:2}
.info-panel .iplbl{color:var(--text3);font-weight:600}.info-panel .ipval{color:var(--cyan);font-weight:600}
@media(max-width:768px){.stats{grid-template-columns:repeat(2,1fr)}.stat .num{font-size:1.5em}}
"""

LOGIN_HTML = f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>XBZ PRO</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet"><style>{LOGIN_CSS}</style></head><body><div class="login-card"><div class="icon">⚡</div><h1>XBZ PRO</h1><div class="ver">v{VERSION}</div><div class="sub">پنل مدیریت VPN</div>{{% if error %}}<div class="err">{{{{error}}}}</div>{{% endif %}}<form method="POST"><div class="field"><label>نام کاربری</label><input name="username" placeholder="نام کاربری" required></div><div class="field"><label>رمز عبور</label><input name="password" type="password" placeholder="رمز عبور" required></div><button type="submit" class="btn-login">ورود به پنل</button></form></div></body></html>"""

SETTINGS_HTML = f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Settings</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet"><style>{DASH_CSS}</style></head><body><div class="nav"><div class="nav-brand"><h2>⚡ <span>XBZ PRO</span></h2><span class="v">v{{{{version}}}}</span></div><div class="nav-links"><a href="/">🏠 داشبورد</a><a href="/logout" class="btn-logout">🚪 خروج</a></div></div><div class="ct" style="max-width:700px"><div class="sec"><div class="sec-header"><h3><span class="emoji">⚙️</span> تنظیمات پنل</h3></div><form method="POST"><div class="field"><label>نام پنل</label><input name="panel_title" value="{{{{title}}}}"></div><div class="field"><label>دامنه سرور</label><input name="server_domain" value="{{{{domain}}}}"></div><div class="field"><label>پورت سرور</label><input name="server_port" value="{{{{port}}}}"></div><div class="field"><label>مسیر اشتراک</label><input name="sub_path" value="{{{{sub_path}}}}"></div><button type="submit" class="btn btn-primary" style="width:100%;padding:14px;font-size:1em;margin-top:8px">💾 ذخیره تنظیمات</button></form><div style="margin-top:20px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius2);padding:20px;font-size:0.85em;color:var(--text2);line-height:2.2"><strong style="color:var(--mauve)">📌 آدرس‌های مهم:</strong><br><span style="color:var(--text3)">لینک اشتراک:</span> <code style="color:var(--mauve);background:rgba(203,166,247,0.1);padding:3px 10px;border-radius:6px;font-size:0.9em">{{{{domain}}}}:{{{{port}}}}{{{{sub_path}}}}/{{{{UUID}}}}</code><br><span style="color:var(--text3)">صفحه اشتراک:</span> <code style="color:var(--mauve);background:rgba(203,166,247,0.1);padding:3px 10px;border-radius:6px;font-size:0.9em">{{{{domain}}}}:{{{{port}}}}/share/{{{{UUID}}}}</code><br><span style="color:var(--text3)">سازگار با:</span> v2rayNG · Hiddify · Nekobox · V2Box · Streisand · Sing-box</div></div></div></body></html>"""

SHARE_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>""" + """{{email}} - {{panel_name}}</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet"><style>""" + COMMON_CSS + """
.share-page{max-width:480px;margin:0 auto;padding:20px 16px}
.share-header{text-align:center;margin-bottom:24px}
.share-header .icon{font-size:2.5em;margin-bottom:8px}
.share-header h1{color:var(--text);font-size:1.5em;font-weight:800}
.share-header .sub{color:var(--text3);font-size:0.9em;margin-top:4px}
.info-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius2);padding:20px;margin-bottom:16px}
.info-card .row{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)}
.info-card .row:last-child{border:none}
.info-card .row .lbl{color:var(--text3);font-size:0.82em;font-weight:600}
.info-card .row .val{color:var(--text);font-size:0.88em;font-weight:700;text-align:left}
.usage-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius2);padding:20px;margin-bottom:16px}
.usage-bar{height:8px;background:var(--bg2);border-radius:4px;overflow:hidden;margin:12px 0}
.usage-fill{height:100%;background:linear-gradient(90deg,var(--mauve),var(--pink));border-radius:4px}
.usage-info{display:flex;justify-content:space-between;font-size:0.8em;color:var(--text3)}
.sub-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius2);padding:20px;margin-bottom:16px}
.sub-card h3{color:var(--text);font-size:1em;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.sub-row{display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border)}
.sub-row:last-child{border:none}
.sub-row .info{flex:1;min-width:0}
.sub-row .lbl{color:var(--text3);font-size:0.75em;font-weight:600;margin-bottom:2px}
.sub-row .val{font-size:0.78em;color:var(--text2);font-weight:600;font-family:'Fira Code',monospace;direction:ltr;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sub-row .actions{display:flex;gap:6px;margin-right:12px}
.act-btn{width:36px;height:36px;border-radius:10px;border:none;display:flex;align-items:center;justify-content:center;font-size:1em;transition:0.2s}
.act-copy{background:rgba(137,180,250,0.12);color:var(--blue)}.act-copy:hover{background:rgba(137,180,250,0.25)}
.act-qr{background:rgba(203,166,247,0.12);color:var(--mauve)}.act-qr:hover{background:rgba(203,166,247,0.25)}
.copy-all{width:100%;padding:16px;background:linear-gradient(135deg,var(--mauve),var(--pink));border:none;border-radius:var(--radius);color:var(--bg);font-size:1em;font-weight:700;transition:0.3s}
.copy-all:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(203,166,247,0.3)}
.qr-box{text-align:center;padding:20px;display:none}
.qr-box img{border-radius:var(--radius2);border:2px solid var(--border)}
.plat-btns{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px}
.plat-btn{padding:16px;border:none;border-radius:var(--radius);font-size:0.9em;font-weight:700;transition:0.2s;display:flex;align-items:center;justify-content:center;gap:8px}
.plat-android{background:rgba(137,180,250,0.15);color:var(--blue);border:1px solid rgba(137,180,250,0.2)}
.plat-ios{background:rgba(203,166,247,0.15);color:var(--mauve);border:1px solid rgba(203,166,247,0.2)}
.plat-btn:hover{opacity:0.85}
.toast{position:fixed;bottom:32px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,var(--mauve),var(--pink));color:var(--bg);padding:14px 28px;border-radius:var(--radius);font-size:0.9em;font-weight:600;display:none;z-index:200;box-shadow:0 8px 30px rgba(203,166,247,0.3)}
.badge{display:inline-flex;align-items:center;gap:4px;padding:4px 12px;border-radius:20px;font-size:0.75em;font-weight:600}
.bg{background:rgba(166,227,161,0.12);color:var(--green)}.br{background:rgba(243,139,168,0.12);color:var(--red)}.bp{background:rgba(203,166,247,0.12);color:var(--mauve)}
</style></head><body>
<div class="share-page">
<div class="share-header"><div class="icon">⚡</div><h1>{{panel_name}}</h1><div class="sub">{{email}}</div></div>

<div class="info-card">
<div class="row"><span class="lbl">شناسه اشتراک</span><span class="val" style="font-size:0.72em;font-family:'Fira Code',monospace;direction:ltr">{{uuid}}</span></div>
<div class="row"><span class="lbl">ایمیل</span><span class="val">{{email}}</span></div>
<div class="row"><span class="lbl">وضعیت</span><span class="val">{% if enable %}<span class="badge bg">✅ فعال</span>{% else %}<span class="badge br">❌ غیرفعال</span>{% endif %}</span></div>
<div class="row"><span class="lbl">پروتکل</span><span class="val"><span class="badge bp">{{protocol}}</span></span></div>
<div class="row"><span class="lbl">دانلود</span><span class="val">{{traffic_str}}</span></div>
<div class="row"><span class="lbl">آپلود</span><span class="val">{{up_str}}</span></div>
<div class="row"><span class="lbl">حجم کل</span><span class="val">{{total_str}}</span></div>
<div class="row"><span class="lbl">تاریخ انقضا</span><span class="val">{{exp_str}}</span></div>
</div>

<div class="usage-card">
<div class="usage-info"><span>{{traffic_str}} / {{total_str}}</span><span class="badge bp">⚡ {% if total_bytes > 0 %}{{usage_pct}}%{% else %}∞{% endif %}</span></div>
<div class="usage-bar"><div class="usage-fill" style="width:{{usage_pct}}%"></div></div>
</div>

<div class="sub-card">
<h3>🔗 اطلاعات اشتراک</h3>
<div class="sub-row"><div class="info"><div class="lbl">لینک اشتراک (SUB)</div><div class="val">{{sub_url}}</div></div><div class="actions"><button class="act-btn act-copy" onclick="copyT('{{sub_url}}')">📋</button><button class="act-btn act-qr" onclick="showQR()">📱</button></div></div>
<div class="sub-row"><div class="info"><div class="lbl">لینک VPN</div><div class="val">{{link}}</div></div><div class="actions"><button class="act-btn act-copy" onclick="copyT('{{link}}')">📋</button></div></div>
<div class="sub-row"><div class="info"><div class="lbl">اطلاعات کاربر</div><div class="val">{{info_url}}</div></div><div class="actions"><button class="act-btn act-copy" onclick="copyT('{{info_url}}')">📋</button></div></div>
</div>

<button class="copy-all" onclick="copyT('{{link}}')">📋 کپی لینک VPN</button>

<div class="qr-box" id="qrBox"><img src="data:image/png;base64,{{qr_data}}" width="220"></div>

<div class="plat-btns">
<button class="plat-btn plat-android" onclick="copyT('{{sub_url}}')"><span>🤖</span>Android</button>
<button class="plat-btn plat-ios" onclick="copyT('{{sub_url}}')"><span>🍎</span>iOS</button>
</div>
</div>
<div class="toast" id="toast">✅ کپی شد!</div>
<script>function copyT(t){navigator.clipboard.writeText(t).then(()=>{var e=document.getElementById('toast');e.style.display='block';setTimeout(()=>e.style.display='none',2000)})}function showQR(){var b=document.getElementById('qrBox');b.style.display=b.style.display==='block'?'none':'block'}</script>
</body></html>"""

DASH_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>""" + """{{panel_name}} v{{version}}</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet"><style>""" + DASH_CSS + """</style></head><body>
<div class="nav"><div class="nav-brand"><h2>⚡ <span>XBZ PRO</span></h2><span class="v">v{{version}}</span></div><div class="nav-links"><a href="/settings">⚙️ تنظیمات</a><a href="/api/export" target="_blank">📦 خروجی</a><a href="/logout" class="btn-logout">🚪 خروج</a></div></div>
<div class="ct">
<div class="stats">
<div class="stat purple"><div class="num">{{total_inbounds}}</div><div class="label">اینباندها</div></div>
<div class="stat blue"><div class="num">{{total_users}}</div><div class="label">کل کاربران</div></div>
<div class="stat green"><div class="num">{{active_users}}</div><div class="label">فعال</div></div>
<div class="stat orange"><div class="num">{{expired_users}}</div><div class="label">منقضی شده</div></div>
<div class="stat red"><div class="num">{{'%0.1f'|format(total_down/1073741824)}} GB</div><div class="label">دانلود کل</div></div>
</div>

<div class="sec"><div class="sec-header"><h3><span class="emoji">📡</span> اینباندها</h3><button class="btn btn-primary" onclick="showM('inM')">➕ ایجاد جدید</button></div>
<div style="overflow-x:auto"><table><thead><tr><th>#</th><th>نام</th><th>پروتکل</th><th>پورت</th><th>Domain</th><th>SNI</th><th>شبکه</th><th>وضعیت</th><th>عملیات</th></tr></thead>
<tbody>{% for i in inbounds %}<tr><td>{{i.id}}</td><td style="font-weight:700">{{i.name}}</td><td><span class="badge bp">{{i.protocol|upper}}</span></td><td>{{i.port}}</td><td style="font-size:0.78em">{{i.domain}}</td><td style="font-size:0.78em">{{i.sni}}</td><td>{{i.network}}</td><td>{% if i.enable %}<span class="badge bg">فعال</span>{% else %}<span class="badge br">غیرفعال</span>{% endif %}</td><td><div class="btn-group"><button class="btn btn-warning" onclick="togIn({{i.id}})">🔄</button><button class="btn btn-danger" onclick="delIn({{i.id}})">🗑️</button></div></td></tr>{% endfor %}</tbody></table></div></div>

<div class="sec"><div class="sec-header"><h3><span class="emoji">👤</span> کاربران</h3><div style="display:flex;gap:8px"><button class="btn btn-primary" onclick="showM('usM')">➕ کاربر جدید</button><button class="btn btn-success" onclick="showM('batchM')">👥 ساخت گروهی</button></div></div>
<div style="overflow-x:auto"><table><thead><tr><th>#</th><th>نام</th><th>UUID</th><th>اینباند</th><th>ترافیک</th><th>انقضا</th><th>وضعیت</th><th>عملیات</th></tr></thead>
<tbody>{% for u in users %}<tr><td>{{u.id}}</td><td style="font-weight:700">{{u.email}}</td><td class="uuid-text">{{u.uuid[:16]}}...</td><td>{{u.inb_name or '-'}} <span class="badge bp" style="font-size:0.65em">{{u.inb_proto or ''}}</span></td><td class="traffic">{{'%0.2f'|format(u.up/1073741824)}}↑ / {{'%0.2f'|format(u.down/1073741824)}}↓ GB</td><td class="traffic">{{u.expiry//86400}} روز</td><td>{% if u.enable %}<span class="badge bg">فعال</span>{% else %}<span class="badge br">غیرفعال</span>{% endif %}</td><td><div class="btn-group"><button class="btn btn-info" onclick="getL({{u.id}})" title="لینک">🔗</button><button class="btn btn-purple" onclick="shareP('{{u.uuid}}')" title="صفحه">👁️</button><button class="btn btn-cyan" onclick="showInfo({{u.id}})" title="اطلاعات">📊</button><button class="btn btn-warning" onclick="togU({{u.id}})">🔄</button><button class="btn btn-danger" onclick="delU({{u.id}})">🗑️</button></div></td></tr>{% endfor %}</tbody></table></div>
<div id="lbox" class="cb"></div><div id="infoPanel" class="info-panel"></div></div>
</div>

<div class="mo" id="inM"><div class="md"><div class="md-header"><h3>➕ ایجاد اینباند جدید</h3><button class="md-close" onclick="hideM('inM')">✕</button></div>
<div class="fr"><input id="i-name" placeholder="نام اینباند" value="VLESS-NL" style="flex:1"><select id="i-proto"><option value="vless">VLESS</option><option value="vmess">VMess</option><option value="trojan">Trojan</option></select><input id="i-port" placeholder="پورت" value="443" type="number" style="width:80px"></div>
<div class="fr"><input id="i-domain" placeholder="Domain" style="flex:1"><input id="i-sni" placeholder="SNI" style="flex:1"></div>
<div class="fr"><input id="i-host" placeholder="Host" style="flex:1"><input id="i-path" placeholder="Path" value="/ws" style="width:100px"></div>
<div class="fr"><select id="i-net"><option value="ws">WebSocket</option><option value="grpc">gRPC</option><option value="tcp">TCP</option></select><select id="i-sec"><option value="none">None</option><option value="tls">TLS</option></select><button class="btn btn-primary" onclick="addIn()" style="padding:10px 24px">ذخیره</button></div></div></div>

<div class="mo" id="usM"><div class="md"><div class="md-header"><h3>➕ کاربر جدید</h3><button class="md-close" onclick="hideM('usM')">✕</button></div>
<div class="fr"><input id="u-email" placeholder="نام کاربری" style="flex:1"></div>
<div class="fr"><select id="u-inbound" style="width:100%">{% for i in inbounds %}<option value="{{i.id}}">{{i.name}} ({{i.protocol}}:{{i.port}})</option>{% endfor %}</select></div>
<div class="fr"><input id="u-exp" placeholder="روز" type="number" value="30" style="width:80px"><input id="u-total" placeholder="GB (0=∞)" type="number" value="0" style="width:100px"><input id="u-limitip" placeholder="محدودیت IP" type="number" value="0" style="width:100px"></div>
<div class="fr"><input id="u-tgid" placeholder="Telegram ID" style="flex:1"><input id="u-comment" placeholder="توضیحات" style="flex:1"></div>
<div class="fr"><button class="btn btn-primary" onclick="addU()" style="width:100%;padding:12px">ذخیره کاربر</button></div></div></div>

<div class="mo" id="batchM"><div class="md"><div class="md-header"><h3>👥 ساخت گروهی کاربر</h3><button class="md-close" onclick="hideM('batchM')">✕</button></div>
<div class="fr"><input id="b-count" placeholder="تعداد" type="number" value="10" style="width:80px"><input id="b-prefix" placeholder="پیشوند نام" value="user" style="width:140px"></div>
<div class="fr"><select id="b-inbound" style="width:100%">{% for i in inbounds %}<option value="{{i.id}}">{{i.name}} ({{i.protocol}}:{{i.port}})</option>{% endfor %}</select></div>
<div class="fr"><input id="b-exp" placeholder="روز" type="number" value="30" style="width:80px"><input id="b-total" placeholder="GB" type="number" value="0" style="width:100px"></div>
<div class="fr"><button class="btn btn-success" onclick="batchAdd()" style="width:100%;padding:12px">👥 ساختن گروهی</button></div>
<div id="batchResult" style="margin-top:14px;font-size:0.85em;color:var(--green);line-height:2"></div></div></div>

<div class="toast" id="toast">✅ کپی شد!</div>

<script>
function showM(id){document.getElementById(id).classList.add('show')}
function hideM(id){document.getElementById(id).classList.remove('show')}
function g(id){return document.getElementById(id).value}
function toast(){var t=document.getElementById('toast');t.style.display='block';setTimeout(()=>t.style.display='none',2000)}
function addIn(){fetch("/api/inbound/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:g("i-name"),protocol:g("i-proto"),port:g("i-port"),domain:g("i-domain"),sni:g("i-sni"),host:g("i-host"),path:g("i-path"),network:g("i-net"),security:g("i-sec")})}).then(r=>r.json()).then(d=>{if(d.success)location.reload()})}
function delIn(id){if(confirm("حذف شود؟"))fetch("/api/inbound/delete/"+id,{method:"POST"}).then(()=>location.reload())}
function togIn(id){fetch("/api/inbound/toggle/"+id,{method:"POST"}).then(()=>location.reload())}
function addU(){fetch("/api/user/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:g("u-email"),inbound_id:g("u-inbound"),expiry:g("u-exp"),total:g("u-total"),limit_ip:g("u-limitip"),tg_id:g("u-tgid"),comment:g("u-comment")})}).then(r=>r.json()).then(d=>{if(d.success)location.reload()})}
function delU(id){if(confirm("حذف شود؟"))fetch("/api/user/delete/"+id,{method:"POST"}).then(()=>location.reload())}
function togU(id){fetch("/api/user/toggle/"+id,{method:"POST"}).then(()=>location.reload())}
function getL(id){fetch("/api/link/"+id).then(r=>r.json()).then(d=>{var b=document.getElementById("lbox");b.style.display="block";b.innerHTML="<strong style='color:var(--mauve)'>🔗 لینک VPN:</strong><br>"+d.link+"<br><br><strong style='color:var(--mauve)'>📋 لینک اشتراک:</strong><br>"+window.location.origin+"/sub/"+d.uuid+"<br><br><strong style='color:var(--mauve)'>📊 اطلاعات:</strong><br>"+window.location.origin+"/sub/"+d.uuid+"/info";navigator.clipboard.writeText(d.link||"").then(()=>toast())})}
function shareP(uuid){window.open("/share/"+uuid,"_blank")}
function showInfo(id){fetch("/api/user/info/"+id).then(r=>r.json()).then(d=>{var p=document.getElementById("infoPanel");p.style.display="block";p.innerHTML="<strong style='color:var(--mauve)'>📊 اطلاعات کاربر:</strong><br><span class='iplbl'>نام:</span> <span class='ipval'>"+d.email+"</span><br><span class='iplbl'>UUID:</span> <span class='ipval'>"+d.uuid+"</span><br><span class='iplbl'>پروتکل:</span> <span class='ipval'>"+d.protocol+"</span><br><span class='iplbl'>دامنه:</span> <span class='ipval'>"+d.domain+"</span><br><span class='iplbl'>آپلود:</span> <span class='ipval'>"+d.traffic_up+"</span><br><span class='iplbl'>دانلود:</span> <span class='ipval'>"+d.traffic_down+"</span><br><span class='iplbl'>حجم کل:</span> <span class='ipval'>"+d.traffic_total+"</span><br><span class='iplbl'>انقضا:</span> <span class='ipval'>"+d.expiry_date+"</span><br><span class='iplbl'>آخرین ورود:</span> <span class='ipval'>"+(d.last_login||'هیچوقت')+"</span><br><span class='iplbl'>لینک ساب:</span> <span class='ipval'>"+window.location.origin+"/sub/"+d.uuid+"</span>";window.scrollTo({top:p.offsetTop-100,behavior:'smooth'})})}
function batchAdd(){fetch("/api/user/batch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({count:g("b-count"),prefix:g("b-prefix"),inbound_id:g("b-inbound"),expiry:g("b-exp"),total:g("b-total")})}).then(r=>r.json()).then(d=>{if(d.success){var r=document.getElementById("batchResult");r.innerHTML="✅ "+d.count+" کاربر ساخته شد!<br><br>";d.users.forEach(u=>{r.innerHTML+="<code style='color:var(--text2)'>"+u.email+"</code> → <code style='color:var(--mauve)'>"+u.uuid+"</code><br>"});r.innerHTML+="<br><button class='btn btn-primary' onclick='location.reload()'>بازخوانی</button>"}})}
</script></body></html>"""

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)
