import os, json, uuid, sqlite3, secrets, base64, time
from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify, Response
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_USER = os.environ.get("ADMIN_USER", "xbz")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "xbz2026")
DB = "xbz.db"
VERSION = "1.7.5"

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
    tup = sum(u["up"] for u in users); tdn = sum(u["down"] for u in users)
    ti = len(inbounds); now = time.time()
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

@app.route("/api/user/reset/<int:uid>", methods=["POST"])
@login_required
def reset_user(uid):
    db = get_db(); db.execute("UPDATE users_vpn SET up=0, down=0 WHERE id=?", (uid,))
    db.commit(); db.close(); return jsonify({"success":True})

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
    dn = f"{user['down']/1073741824:.2f} GB"; up = f"{user['up']/1073741824:.2f} GB"
    tn = f"{user['total']/1073741824:.2f} GB" if user['total'] else "∞"
    sub_url = f"{request.host_url}sub/{token}"; info_url = f"{request.host_url}sub/{token}/info"
    import qrcode, io as _io, base64 as _b64
    qr = qrcode.make(link); buf = _io.BytesIO(); qr.save(buf, format='PNG'); buf.seek(0)
    qr_b64 = _b64.b64encode(buf.getvalue()).decode()
    usage_pct = min(100, int((user['up']+user['down'])/user['total']*100)) if user['total'] > 0 else 0
    db.close()
    return render_template_string(SHARE_HTML, link=link, email=user["email"], uuid=user["uuid"],
        protocol=user["protocol"].upper(), domain=user["domain"], port=user["port"], qr_data=qr_b64,
        exp_str=exp_str, traffic_str=dn, total_str=tn, up_str=up, sub_url=sub_url, info_url=info_url,
        enable=user["enable"], panel_name=gs("panel_title"), usage_pct=usage_pct,
        dn_bytes=user['down'], up_bytes=user['up'], total_bytes=user['total'])

@app.route("/api/user/batch", methods=["POST"])
@login_required
def batch_add():
    d = request.json; count = min(int(d.get("count", 1)), 100)
    prefix = d.get("prefix", "user"); inbound_id = int(d.get("inbound_id", 0))
    expiry = int(d.get("expiry", 30)) * 86400; total = int(d.get("total", 0)) * 1073741824
    db = get_db(); created = []
    for i in range(count):
        u = str(uuid.uuid4()); email = f"{prefix}-{i+1}"
        db.execute("INSERT INTO users_vpn (email,uuid,enable,total,expiry,inbound_id) VALUES (?,?,1,?,?,?)",
                   (email, u, total, expiry, inbound_id))
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

# ═══════════════════════════════════════════════════════
# ═══════════ MARZBAN-STYLE CSS ═══════════════════════
# ═══════════════════════════════════════════════════════

CSS = """
:root{--bg:#0f0f1a;--bg2:#16162a;--card:#1c1c30;--card2:#22223a;
--border:rgba(255,255,255,0.06);--border2:rgba(255,255,255,0.1);
--text:#e2e2f0;--text2:#a0a0c0;--text3:#606080;
--purple:#9d6bff;--purple2:#b388ff;--pink:#ff6bcb;--pink2:#ff4081;
--green:#4cff8d;--green2:#00e676;--red:#ff5277;--red2:#ff1744;
--blue:#5c8cff;--cyan:#00e5ff;--orange:#ffab40;--yellow:#ffd740;
--mauve:#b388ff;--overlay:rgba(0,0,0,0.55);--r:12px;--r2:16px;--r3:20px;
--shadow:0 4px 24px rgba(0,0,0,0.25)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--text3);border-radius:3px}
"""

LOGIN_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>XBZ PRO - Login</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>""" + CSS + """
body{display:flex;align-items:center;justify-content:center;overflow:hidden;position:relative}
body::before{content:'';position:fixed;inset:0;background:
  radial-gradient(ellipse 600px 400px at 25% 15%,rgba(157,107,255,0.12),transparent),
  radial-gradient(ellipse 500px 400px at 75% 85%,rgba(255,107,203,0.08),transparent),
  radial-gradient(ellipse 300px 300px at 50% 50%,rgba(157,107,255,0.04),transparent);
  z-index:0}
.login-wrap{position:relative;z-index:1;display:flex;align-items:center;justify-content:center;min-height:100vh;width:100%}
.login-card{background:var(--card);border:1px solid var(--border2);border-radius:24px;padding:48px 44px;width:440px;max-width:92vw;box-shadow:var(--shadow);backdrop-filter:blur(20px);text-align:center}
.login-logo{width:72px;height:72px;margin:0 auto 20px;background:linear-gradient(135deg,var(--purple),var(--pink));border-radius:20px;display:flex;align-items:center;justify-content:center;font-size:2.2em;box-shadow:0 8px 32px rgba(157,107,255,0.25)}
.login-card h1{color:var(--text);font-size:1.8em;font-weight:800;margin-bottom:6px;letter-spacing:-0.5px}
.login-card .ver{color:var(--purple);font-size:0.78em;font-weight:700;margin-bottom:6px}
.login-card .desc{color:var(--text3);font-size:0.88em;margin-bottom:36px}
.field{margin-bottom:18px;text-align:right}
.field label{display:block;color:var(--text2);font-size:0.8em;font-weight:600;margin-bottom:8px}
.field input{width:100%;padding:14px 18px;border:1.5px solid var(--border2);border-radius:var(--r);background:var(--bg2);color:var(--text);font-size:0.95em;transition:all 0.3s}
.field input:focus{border-color:var(--purple);outline:none;box-shadow:0 0 0 4px rgba(157,107,255,0.1)}
.field input::placeholder{color:var(--text3)}
.btn-login{width:100%;padding:15px;background:linear-gradient(135deg,var(--purple),var(--pink));border:none;border-radius:var(--r);color:#fff;font-size:1em;font-weight:700;cursor:pointer;transition:all 0.3s;margin-top:4px;letter-spacing:0.3px}
.btn-login:hover{transform:translateY(-2px);box-shadow:0 8px 28px rgba(157,107,255,0.35)}
.btn-login:active{transform:translateY(0)}
.err{color:var(--red);margin-bottom:18px;font-size:0.85em;background:rgba(255,82,119,0.08);padding:12px 16px;border-radius:var(--r);border:1px solid rgba(255,82,119,0.15);text-align:right}
.login-footer{margin-top:28px;color:var(--text3);font-size:0.75em}
.login-footer a{color:var(--purple);text-decoration:none}
.forgot{display:inline-block;margin-top:12px;color:var(--purple);font-size:0.82em;cursor:pointer;transition:0.2s}.forgot:hover{color:var(--pink)}
</style></head><body>
<div class="login-wrap"><div class="login-card">
<div class="login-logo">⚡</div>
<h1>XBZ PRO</h1>
<div class="ver">v""" + VERSION + """</div>
<div class="desc">پنل مدیریت VPN</div>
{% if error %}<div class="err">⚠️ {{error}}</div>{% endif %}
<form method="POST">
<div class="field"><label>نام کاربری</label><input name="username" placeholder="نام کاربری خود را وارد کنید" required autocomplete="username"></div>
<div class="field"><label>رمز عبور</label><input name="password" type="password" placeholder="رمز عبور خود را وارد کنید" required autocomplete="current-password"></div>
<button type="submit" class="btn-login">ورود به پنل</button>
</form>
<div class="login-footer">v""" + VERSION + """ · XBZ PRO Panel</div>
</div></div></body></html>"""

SETTINGS_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Settings</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>""" + CSS + """
.nav{background:var(--bg2);padding:0 32px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);height:60px}
.nav-brand{display:flex;align-items:center;gap:10px}.nav-brand h2{color:var(--text);font-size:1.15em;font-weight:800}.nav-brand h2 span{color:var(--purple)}
.nav-brand .v{color:var(--text3);font-size:0.7em;font-weight:700;background:var(--card);padding:3px 10px;border-radius:20px;border:1px solid var(--border)}
.nav-links{display:flex;gap:6px;align-items:center}.nav-links a{color:var(--text3);padding:8px 16px;border-radius:var(--r);font-size:0.85em;font-weight:600;transition:0.2s;text-decoration:none}.nav-links a:hover{background:var(--card);color:var(--text)}
.ct{max-width:680px;margin:36px auto;padding:0 24px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--r3);padding:28px;margin-bottom:20px}
.card h3{color:var(--text);font-size:1.05em;font-weight:700;margin-bottom:22px;display:flex;align-items:center;gap:8px}
.field{margin-bottom:16px;text-align:right}.field label{display:block;color:var(--text3);font-size:0.8em;font-weight:600;margin-bottom:6px}
.field input{width:100%;padding:12px 16px;border:1.5px solid var(--border2);border-radius:var(--r);background:var(--bg2);color:var(--text);font-size:0.92em;transition:0.3s}
.field input:focus{border-color:var(--purple);outline:none}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,var(--purple),var(--pink));border:none;border-radius:var(--r);color:#fff;font-size:0.95em;font-weight:700;cursor:pointer;transition:0.3s}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 28px rgba(157,107,255,0.3)}
.info{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r2);padding:18px;margin-top:18px;font-size:0.82em;color:var(--text2);line-height:2.2}
.info strong{color:var(--purple)}.info code{color:var(--purple);background:rgba(157,107,255,0.1);padding:3px 10px;border-radius:6px;font-size:0.92em}
</style></head><body>
<div class="nav"><div class="nav-brand"><h2>⚡ <span>XBZ PRO</span></h2><span class="v">v""" + VERSION + """</span></div><div class="nav-links"><a href="/">🏠 داشبورد</a><a href="/logout">🚪 خروج</a></div></div>
<div class="ct"><div class="card"><h3>⚙️ تنظیمات پنل</h3>
<form method="POST"><div class="field"><label>نام پنل</label><input name="panel_title" value="{{title}}"></div>
<div class="field"><label>دامنه سرور</label><input name="server_domain" value="{{domain}}"></div>
<div class="field"><label>پورت سرور</label><input name="server_port" value="{{port}}"></div>
<div class="field"><label>مسیر اشتراک</label><input name="sub_path" value="{{sub_path}}"></div>
<button type="submit" class="btn">💾 ذخیره تنظیمات</button></form>
<div class="info"><strong>📌 آدرس‌های اشتراک:</strong><br>لینک ساب: <code>{{domain}}:{{port}}{{sub_path}}/{{UUID}}</code><br>صفحه اشتراک: <code>{{domain}}:{{port}}/share/{{UUID}}</code><br>سازگار با: v2rayNG · Hiddify · Nekobox · V2Box · Streisand</div></div></div></body></html>"""

SHARE_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{email}} - {{panel_name}}</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>""" + CSS + """
.page{max-width:480px;margin:0 auto;padding:20px 16px}
.hdr{text-align:center;margin-bottom:24px}
.hdr .ic{font-size:2.8em;margin-bottom:8px}.hdr h1{color:var(--text);font-size:1.5em;font-weight:800}.hdr .s{color:var(--text3);font-size:0.88em;margin-top:4px}
.info-card{background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:20px;margin-bottom:14px}
.row{display:flex;justify-content:space-between;align-items:center;padding:11px 0;border-bottom:1px solid var(--border)}.row:last-child{border:none}
.row .l{color:var(--text3);font-size:0.8em;font-weight:600}.row .v{color:var(--text);font-size:0.85em;font-weight:700;text-align:left}
.badge{display:inline-flex;align-items:center;gap:4px;padding:4px 12px;border-radius:20px;font-size:0.75em;font-weight:600}
.bg{background:rgba(76,255,141,0.1);color:var(--green)}.br{background:rgba(255,82,119,0.1);color:var(--red)}.bp{background:rgba(157,107,255,0.1);color:var(--purple)}
.usage-card{background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:18px;margin-bottom:14px}
.bar-wrap{height:8px;background:var(--bg2);border-radius:4px;overflow:hidden;margin:10px 0}.bar-fill{height:100%;background:linear-gradient(90deg,var(--purple),var(--pink));border-radius:4px}
.bar-info{display:flex;justify-content:space-between;font-size:0.78em;color:var(--text3)}
.sub-card{background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:20px;margin-bottom:14px}
.sub-card h3{color:var(--text);font-size:0.95em;font-weight:700;margin-bottom:14px}
.srow{display:flex;align-items:center;justify-content:space-between;padding:11px 0;border-bottom:1px solid var(--border)}.srow:last-child{border:none}
.srow .inf{flex:1;min-width:0}.srow .lbl{color:var(--text3);font-size:0.72em;font-weight:600;margin-bottom:2px}.srow .vl{font-size:0.75em;color:var(--text2);font-weight:600;font-family:monospace;direction:ltr;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.srow .act{display:flex;gap:6px;margin-right:12px}
.abtn{width:34px;height:34px;border-radius:9px;border:none;display:flex;align-items:center;justify-content:center;font-size:0.95em;transition:0.2s;cursor:pointer}
.ac{background:rgba(92,140,255,0.1);color:var(--blue)}.ac:hover{background:rgba(92,140,255,0.2)}
.aq{background:rgba(157,107,255,0.1);color:var(--purple)}.aq:hover{background:rgba(157,107,255,0.2)}
.cpy{width:100%;padding:15px;background:linear-gradient(135deg,var(--purple),var(--pink));border:none;border-radius:var(--r);color:#fff;font-size:0.95em;font-weight:700;cursor:pointer;transition:0.3s}
.cpy:hover{transform:translateY(-2px);box-shadow:0 8px 28px rgba(157,107,255,0.3)}
.qr{text-align:center;padding:18px;display:none}.qr img{border-radius:var(--r2);border:2px solid var(--border)}
.pbtns{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px}
.pbtn{padding:15px;border:none;border-radius:var(--r);font-size:0.88em;font-weight:700;cursor:pointer;transition:0.2s;display:flex;align-items:center;justify-content:center;gap:8px}
.pa{background:rgba(92,140,255,0.12);color:var(--blue);border:1px solid rgba(92,140,255,0.2)}
.pi{background:rgba(157,107,255,0.12);color:var(--purple);border:1px solid rgba(157,107,255,0.2)}
.pbtn:hover{opacity:0.85}
.toast{position:fixed;bottom:32px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,var(--purple),var(--pink));color:#fff;padding:12px 28px;border-radius:var(--r);font-size:0.88em;font-weight:600;display:none;z-index:100;box-shadow:0 8px 28px rgba(157,107,255,0.3)}
</style></head><body>
<div class="page">
<div class="hdr"><div class="ic">⚡</div><h1>{{panel_name}}</h1><div class="s">{{email}}</div></div>
<div class="info-card">
<div class="row"><span class="l">شناسه اشتراک</span><span class="v" style="font-size:0.7em;font-family:monospace;direction:ltr">{{uuid}}</span></div>
<div class="row"><span class="l">ایمیل</span><span class="v">{{email}}</span></div>
<div class="row"><span class="l">وضعیت</span><span class="v">{% if enable %}<span class="badge bg">✅ فعال</span>{% else %}<span class="badge br">❌ غیرفعال</span>{% endif %}</span></div>
<div class="row"><span class="l">پروتکل</span><span class="v"><span class="badge bp">{{protocol}}</span></span></div>
<div class="row"><span class="l">دانلود</span><span class="v">{{traffic_str}}</span></div>
<div class="row"><span class="l">آپلود</span><span class="v">{{up_str}}</span></div>
<div class="row"><span class="l">حجم کل</span><span class="v">{{total_str}}</span></div>
<div class="row"><span class="l">انقضا</span><span class="v">{{exp_str}}</span></div>
</div>
<div class="usage-card"><div class="bar-info"><span>{{traffic_str}} / {{total_str}}</span><span class="badge bp">⚡ {% if total_bytes > 0 %}{{usage_pct}}%{% else %}∞{% endif %}</span></div><div class="bar-wrap"><div class="bar-fill" style="width:{{usage_pct}}%"></div></div></div>
<div class="sub-card"><h3>🔗 اطلاعات اشتراک</h3>
<div class="srow"><div class="inf"><div class="lbl">لینک اشتراک (SUB)</div><div class="vl">{{sub_url}}</div></div><div class="act"><button class="abtn ac" onclick="cT('{{sub_url}}')">📋</button><button class="abtn aq" onclick="sQR()">📱</button></div></div>
<div class="srow"><div class="inf"><div class="lbl">لینک VPN</div><div class="vl">{{link}}</div></div><div class="act"><button class="abtn ac" onclick="cT('{{link}}')">📋</button></div></div>
<div class="srow"><div class="inf"><div class="lbl">اطلاعات کاربر</div><div class="vl">{{info_url}}</div></div><div class="act"><button class="abtn ac" onclick="cT('{{info_url}}')">📋</button></div></div>
</div>
<button class="cpy" onclick="cT('{{link}}')">📋 کپی لینک VPN</button>
<div class="qr" id="qrBox"><img src="data:image/png;base64,{{qr_data}}" width="220"></div>
<div class="pbtns"><button class="pbtn pa" onclick="cT('{{sub_url}}')">🤖 Android</button><button class="pbtn pi" onclick="cT('{{sub_url}}')">🍎 iOS</button></div>
</div>
<div class="toast" id="t">✅ کپی شد!</div>
<script>function cT(t){navigator.clipboard.writeText(t).then(()=>{var e=document.getElementById('t');e.style.display='block';setTimeout(()=>e.style.display='none',2000)})}function sQR(){var b=document.getElementById('qrBox');b.style.display=b.style.display==='block'?'none':'block'}</script></body></html>"""

DASH_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{panel_name}} v{{version}}</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>""" + CSS + """
.nav{background:var(--bg2);padding:0 32px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);height:60px;position:sticky;top:0;z-index:50;backdrop-filter:blur(12px)}
.nav-brand{display:flex;align-items:center;gap:10px}.nav-brand h2{color:var(--text);font-size:1.15em;font-weight:800}.nav-brand h2 span{color:var(--purple)}
.nav-brand .v{color:var(--text3);font-size:0.7em;font-weight:700;background:var(--card);padding:3px 10px;border-radius:20px;border:1px solid var(--border)}
.nav-links{display:flex;gap:6px;align-items:center}.nav-links a{color:var(--text3);padding:8px 14px;border-radius:var(--r);font-size:0.83em;font-weight:600;transition:0.2s;text-decoration:none;display:flex;align-items:center;gap:5px}.nav-links a:hover{background:var(--card);color:var(--text)}.nav-links .lo{color:var(--red)}.nav-links .lo:hover{background:rgba(255,82,119,0.08)}
.ct{max-width:1280px;margin:24px auto;padding:0 24px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:24px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:18px 16px;position:relative;overflow:hidden;transition:0.2s}
.stat:hover{border-color:var(--border2);transform:translateY(-2px)}
.stat::before{content:'';position:absolute;top:0;right:0;width:3px;height:100%;border-radius:0 3px 3px 0}
.stat.c1::before{background:var(--purple)}.stat.c2::before{background:var(--blue)}.stat.c3::before{background:var(--green)}.stat.c4::before{background:var(--orange)}.stat.c5::before{background:var(--red)}
.stat .n{font-size:1.9em;font-weight:800;margin-bottom:2px;line-height:1}.stat.c1 .n{color:var(--purple)}.stat.c2 .n{color:var(--blue)}.stat.c3 .n{color:var(--green)}.stat.c4 .n{color:var(--orange)}.stat.c5 .n{color:var(--red)}
.stat .lb{color:var(--text3);font-size:0.78em;font-weight:600}
.sec{background:var(--card);border:1px solid var(--border);border-radius:var(--r3);padding:24px;margin-bottom:22px}
.sec-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.sec-h h3{color:var(--text);font-size:1.05em;font-weight:700;display:flex;align-items:center;gap:8px}
.sec-h h3 .em{font-size:1.15em}
table{width:100%;border-collapse:separate;border-spacing:0}
thead th{padding:11px 14px;text-align:right;font-size:0.7em;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;border-bottom:2px solid var(--border);background:var(--bg2)}
thead th:first-child{border-radius:var(--r) 0 0 0}thead th:last-child{border-radius:0 var(--r) 0 0}
tbody td{padding:11px 14px;font-size:0.83em;border-bottom:1px solid var(--border)}
tbody tr{transition:0.15s}tbody tr:hover{background:rgba(157,107,255,0.03)}
.uuid{font-family:monospace;font-size:0.73em;color:var(--text3);direction:ltr}
.trf{font-size:0.75em;color:var(--text2);direction:ltr;text-align:left}
.btn{padding:5px 12px;border:none;border-radius:8px;font-size:0.76em;font-weight:600;transition:0.2s;cursor:pointer;display:inline-flex;align-items:center;gap:3px}
.bp{background:linear-gradient(135deg,var(--purple),var(--pink));color:#fff}.bp:hover{opacity:0.85}
.bi{background:rgba(92,140,255,0.1);color:var(--blue)}.bi:hover{background:rgba(92,140,255,0.2)}
.bpu{background:rgba(157,107,255,0.1);color:var(--purple)}.bpu:hover{background:rgba(157,107,255,0.2)}
.bc{background:rgba(0,229,255,0.1);color:var(--cyan)}.bc:hover{background:rgba(0,229,255,0.2)}
.bw{background:rgba(255,171,64,0.1);color:var(--orange)}.bw:hover{background:rgba(255,171,64,0.2)}
.bd{background:rgba(255,82,119,0.1);color:var(--red)}.bd:hover{background:rgba(255,82,119,0.2)}
.bs{background:rgba(76,255,141,0.1);color:var(--green)}.bs:hover{background:rgba(76,255,141,0.2)}
.bgrp{display:flex;gap:3px}
.badge{display:inline-flex;padding:3px 10px;border-radius:20px;font-size:0.72em;font-weight:600}
.bg{background:rgba(76,255,141,0.1);color:var(--green)}.br{background:rgba(255,82,119,0.1);color:var(--red)}.bpr{background:rgba(157,107,255,0.1);color:var(--purple)}
input,select{padding:9px 14px;border:1.5px solid var(--border2);border-radius:var(--r);background:var(--bg2);color:var(--text);font-size:0.83em;transition:0.2s}
input:focus,select:focus{border-color:var(--purple);outline:none;box-shadow:0 0 0 3px rgba(157,107,255,0.08)}
select option{background:var(--bg2);color:var(--text)}
.fr{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.cb{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r2);padding:14px;margin-top:12px;word-break:break-all;font-family:monospace;font-size:0.78em;color:var(--green);display:none;line-height:1.6}
.mo{display:none;position:fixed;inset:0;background:var(--overlay);z-index:100;align-items:center;justify-content:center;backdrop-filter:blur(4px)}.mo.show{display:flex}
.md{background:var(--card);border:1px solid var(--border2);border-radius:var(--r3);padding:28px;width:540px;max-width:94vw;max-height:85vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,0.4)}
.md-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px}.md-h h3{color:var(--text);font-size:1.05em;font-weight:700}
.md-x{width:34px;height:34px;border-radius:50%;border:none;background:var(--bg2);color:var(--text3);font-size:1.1em;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:0.2s}.md-x:hover{background:rgba(255,82,119,0.12);color:var(--red)}
.toast{position:fixed;bottom:32px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,var(--purple),var(--pink));color:#fff;padding:12px 28px;border-radius:var(--r);font-size:0.88em;font-weight:600;display:none;z-index:200;box-shadow:0 8px 28px rgba(157,107,255,0.3)}
.ip{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r2);padding:18px;margin-top:12px;display:none;font-size:0.82em;line-height:2}.ip .il{color:var(--text3);font-weight:600}.ip .iv{color:var(--cyan);font-weight:600}
@media(max-width:768px){.stats{grid-template-columns:repeat(2,1fr)}.stat .n{font-size:1.4em}}
</style></head><body>
<div class="nav"><div class="nav-brand"><h2>⚡ <span>XBZ PRO</span></h2><span class="v">v{{version}}</span></div><div class="nav-links"><a href="/settings">⚙️ تنظیمات</a><a href="/api/export" target="_blank">📦 خروجی</a><a href="/logout" class="lo">🚪 خروج</a></div></div>
<div class="ct">
<div class="stats">
<div class="stat c1"><div class="n">{{total_inbounds}}</div><div class="lb">اینباندها</div></div>
<div class="stat c2"><div class="n">{{total_users}}</div><div class="lb">کل کاربران</div></div>
<div class="stat c3"><div class="n">{{active_users}}</div><div class="lb">فعال</div></div>
<div class="stat c4"><div class="n">{{expired_users}}</div><div class="lb">منقضی شده</div></div>
<div class="stat c5"><div class="n">{{'%0.1f'|format(total_down/1073741824)}} GB</div><div class="lb">دانلود کل</div></div>
</div>
<div class="sec"><div class="sec-h"><h3><span class="em">📡</span> اینباندها</h3><button class="btn bp" onclick="showM('inM')">➕ ایجاد جدید</button></div>
<div style="overflow-x:auto"><table><thead><tr><th>#</th><th>نام</th><th>پروتکل</th><th>پورت</th><th>Domain</th><th>SNI</th><th>شبکه</th><th>وضعیت</th><th>عملیات</th></tr></thead>
<tbody>{% for i in inbounds %}<tr><td>{{i.id}}</td><td style="font-weight:700">{{i.name}}</td><td><span class="badge bpr">{{i.protocol|upper}}</span></td><td>{{i.port}}</td><td style="font-size:0.76em">{{i.domain}}</td><td style="font-size:0.76em">{{i.sni}}</td><td>{{i.network}}</td><td>{% if i.enable %}<span class="badge bg">فعال</span>{% else %}<span class="badge br">غیرفعال</span>{% endif %}</td><td><div class="bgrp"><button class="btn bw" onclick="togIn({{i.id}})">🔄</button><button class="btn bd" onclick="delIn({{i.id}})">🗑️</button></div></td></tr>{% endfor %}</tbody></table></div></div>

<div class="sec"><div class="sec-h"><h3><span class="em">👤</span> کاربران</h3><div style="display:flex;gap:6px"><button class="btn bp" onclick="showM('usM')">➕ کاربر جدید</button><button class="btn bs" onclick="showM('batchM')">👥 ساخت گروهی</button></div></div>
<div style="overflow-x:auto"><table><thead><tr><th>#</th><th>نام</th><th>UUID</th><th>اینباند</th><th>ترافیک</th><th>انقضا</th><th>وضعیت</th><th>عملیات</th></tr></thead>
<tbody>{% for u in users %}<tr><td>{{u.id}}</td><td style="font-weight:700">{{u.email}}</td><td class="uuid">{{u.uuid[:16]}}...</td><td>{{u.inb_name or '-'}} <span class="badge bpr" style="font-size:0.63em">{{u.inb_proto or ''}}</span></td><td class="trf">{{'%0.2f'|format(u.up/1073741824)}}↑ / {{'%0.2f'|format(u.down/1073741824)}}↓ GB</td><td class="trf">{{u.expiry//86400}} روز</td><td>{% if u.enable %}<span class="badge bg">فعال</span>{% else %}<span class="badge br">غیرفعال</span>{% endif %}</td><td><div class="bgrp"><button class="btn bi" onclick="getL({{u.id}})" title="لینک">🔗</button><button class="btn bpu" onclick="shareP('{{u.uuid}}')" title="صفحه">👁️</button><button class="btn bc" onclick="showInfo({{u.id}})" title="اطلاعات">📊</button><button class="btn bw" onclick="togU({{u.id}})">🔄</button><button class="btn bd" onclick="delU({{u.id}})">🗑️</button></div></td></tr>{% endfor %}</tbody></table></div>
<div id="lbox" class="cb"></div><div id="ip" class="ip"></div></div></div>

<div class="mo" id="inM"><div class="md"><div class="md-h"><h3>➕ ایجاد اینباند</h3><button class="md-x" onclick="hideM('inM')">✕</button></div>
<div class="fr"><input id="i-n" placeholder="نام" value="VLESS-NL" style="flex:1"><select id="i-p"><option value="vless">VLESS</option><option value="vmess">VMess</option><option value="trojan">Trojan</option></select><input id="i-pt" placeholder="پورت" value="443" type="number" style="width:80px"></div>
<div class="fr"><input id="i-d" placeholder="Domain" style="flex:1"><input id="i-s" placeholder="SNI" style="flex:1"></div>
<div class="fr"><input id="i-h" placeholder="Host" style="flex:1"><input id="i-pa" placeholder="Path" value="/ws" style="width:100px"></div>
<div class="fr"><select id="i-nw"><option value="ws">WebSocket</option><option value="grpc">gRPC</option><option value="tcp">TCP</option></select><select id="i-sc"><option value="none">None</option><option value="tls">TLS</option></select><button class="btn bp" onclick="addIn()" style="padding:9px 20px">ذخیره</button></div></div></div>

<div class="mo" id="usM"><div class="md"><div class="md-h"><h3>➕ کاربر جدید</h3><button class="md-x" onclick="hideM('usM')">✕</button></div>
<div class="fr"><input id="u-e" placeholder="نام کاربری" style="flex:1"></div>
<div class="fr"><select id="u-i" style="width:100%">{% for i in inbounds %}<option value="{{i.id}}">{{i.name}} ({{i.protocol}}:{{i.port}})</option>{% endfor %}</select></div>
<div class="fr"><input id="u-ex" placeholder="روز" type="number" value="30" style="width:80px"><input id="u-t" placeholder="GB (0=∞)" type="number" value="0" style="width:100px"><input id="u-li" placeholder="محدودیت IP" type="number" value="0" style="width:100px"></div>
<div class="fr"><button class="btn bp" onclick="addU()" style="width:100%;padding:11px">ذخیره</button></div></div></div>

<div class="mo" id="batchM"><div class="md"><div class="md-h"><h3>👥 ساخت گروهی</h3><button class="md-x" onclick="hideM('batchM')">✕</button></div>
<div class="fr"><input id="b-c" placeholder="تعداد" type="number" value="10" style="width:80px"><input id="b-p" placeholder="پیشوند" value="user" style="width:140px"></div>
<div class="fr"><select id="b-i" style="width:100%">{% for i in inbounds %}<option value="{{i.id}}">{{i.name}} ({{i.protocol}}:{{i.port}})</option>{% endfor %}</select></div>
<div class="fr"><input id="b-e" placeholder="روز" type="number" value="30" style="width:80px"><input id="b-t" placeholder="GB" type="number" value="0" style="width:100px"></div>
<div class="fr"><button class="btn bs" onclick="bAdd()" style="width:100%;padding:11px">👥 ساختن</button></div>
<div id="bR" style="margin-top:12px;font-size:0.82em;color:var(--green);line-height:2"></div></div></div>

<div class="toast" id="t">✅ کپی شد!</div>
<script>
function showM(id){document.getElementById(id).classList.add('show')}
function hideM(id){document.getElementById(id).classList.remove('show')}
function g(id){return document.getElementById(id).value}
function t(){var e=document.getElementById('t');e.style.display='block';setTimeout(()=>e.style.display='none',2000)}
function addIn(){fetch("/api/inbound/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:g("i-n"),protocol:g("i-p"),port:g("i-pt"),domain:g("i-d"),sni:g("i-s"),host:g("i-h"),path:g("i-pa"),network:g("i-nw"),security:g("i-sc")})}).then(r=>r.json()).then(d=>{if(d.success)location.reload()})}
function delIn(id){if(confirm("حذف شود؟"))fetch("/api/inbound/delete/"+id,{method:"POST"}).then(()=>location.reload())}
function togIn(id){fetch("/api/inbound/toggle/"+id,{method:"POST"}).then(()=>location.reload())}
function addU(){fetch("/api/user/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:g("u-e"),inbound_id:g("u-i"),expiry:g("u-ex"),total:g("u-t"),limit_ip:g("u-li")})}).then(r=>r.json()).then(d=>{if(d.success)location.reload()})}
function delU(id){if(confirm("حذف شود؟"))fetch("/api/user/delete/"+id,{method:"POST"}).then(()=>location.reload())}
function togU(id){fetch("/api/user/toggle/"+id,{method:"POST"}).then(()=>location.reload())}
function getL(id){fetch("/api/link/"+id).then(r=>r.json()).then(d=>{var b=document.getElementById("lbox");b.style.display="block";b.innerHTML="<strong style='color:var(--purple)'>🔗 لینک VPN:</strong><br>"+d.link+"<br><br><strong style='color:var(--purple)'>📋 لینک ساب:</strong><br>"+location.origin+"/sub/"+d.uuid+"<br><br><strong style='color:var(--purple)'>📊 اطلاعات:</strong><br>"+location.origin+"/sub/"+d.uuid+"/info";navigator.clipboard.writeText(d.link||"").then(()=>t())})}
function shareP(uuid){window.open("/share/"+uuid,"_blank")}
function showInfo(id){fetch("/api/user/info/"+id).then(r=>r.json()).then(d=>{var p=document.getElementById("ip");p.style.display="block";p.innerHTML="<strong style='color:var(--purple)'>📊 اطلاعات:</strong><br><span class='il'>نام:</span> <span class='iv'>"+d.email+"</span><br><span class='il'>UUID:</span> <span class='iv'>"+d.uuid+"</span><br><span class='il'>پروتکل:</span> <span class='iv'>"+d.protocol+"</span><br><span class='il'>دامنه:</span> <span class='iv'>"+d.domain+"</span><br><span class='il'>آپلود:</span> <span class='iv'>"+d.traffic_up+"</span><br><span class='il'>دانلود:</span> <span class='iv'>"+d.traffic_down+"</span><br><span class='il'>حجم کل:</span> <span class='iv'>"+d.traffic_total+"</span><br><span class='il'>انقضا:</span> <span class='iv'>"+d.expiry_date+"</span><br><span class='il'>آخرین ورود:</span> <span class='iv'>"+(d.last_login||'—')+"</span><br><span class='il'>لینک ساب:</span> <span class='iv'>"+location.origin+"/sub/"+d.uuid+"</span>";window.scrollTo({top:p.offsetTop-80,behavior:'smooth'})})}
function bAdd(){fetch("/api/user/batch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({count:g("b-c"),prefix:g("b-p"),inbound_id:g("b-i"),expiry:g("b-e"),total:g("b-t")})}).then(r=>r.json()).then(d=>{if(d.success){var r=document.getElementById("bR");r.innerHTML="✅ "+d.count+" کاربر ساخته شد!<br><br>";d.users.forEach(u=>{r.innerHTML+="<code style='color:var(--text2)'>"+u.email+"</code> → <code style='color:var(--purple)'>"+u.uuid+"</code><br>"});r.innerHTML+="<br><button class='btn bp' onclick='location.reload()'>بازخوانی</button>"}})}
</script></body></html>"""

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)
