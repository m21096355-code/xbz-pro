import os, json, uuid, sqlite3, secrets, base64, time
from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify, Response
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

ADMIN_USER = os.environ.get("ADMIN_USER", "xbz")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "xbz2026")
PANEL_NAME = "XBZ PRO"
DB = "xbz.db"

# ─── Database ──────────────────────────────────────────
def init_db():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS inbounds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT DEFAULT '', protocol TEXT DEFAULT 'vless',
        port INTEGER DEFAULT 443, uuid TEXT,
        flow TEXT DEFAULT '', network TEXT DEFAULT 'ws',
        security TEXT DEFAULT 'none', sni TEXT DEFAULT '',
        domain TEXT DEFAULT '', host TEXT DEFAULT '',
        path TEXT DEFAULT '/', remark TEXT DEFAULT '',
        enable INTEGER DEFAULT 1, tag TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS users_vpn (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT, uuid TEXT, enable INTEGER DEFAULT 1,
        up INTEGER DEFAULT 0, down INTEGER DEFAULT 0,
        total INTEGER DEFAULT 0, expiry INTEGER DEFAULT 0,
        inbound_id INTEGER, limit_ip INTEGER DEFAULT 0,
        tg_id TEXT DEFAULT '', comment TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP DEFAULT '')""")
    c.execute("""CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY, value TEXT)""")
    # default settings
    for k, v in [("panel_title","XBZ PRO"),("server_domain","your-domain.com"),
                  ("server_port","443"),("sub_path","/sub")]:
        c.execute("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)", (k,v))
    c.commit(); c.close()

def get_db():
    conn = sqlite3.connect(DB); conn.row_factory = sqlite3.Row; return conn

def get_setting(key, default=""):
    db = get_db()
    r = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    db.close()
    return r["value"] if r else default

def set_setting(key, value):
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, value))
    db.commit(); db.close()

# ─── Auth ───────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return d

@app.route("/login", methods=["GET","POST"])
def login():
    err = None
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USER and request.form.get("password") == ADMIN_PASS:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
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
    total_users = len(users)
    active_users = sum(1 for u in users if u["enable"])
    total_up = sum(u["up"] for u in users)
    total_down = sum(u["down"] for u in users)
    total_inbounds = len(inbounds)
    db.close()
    return render_template_string(DASH_HTML, inbounds=inbounds, users=users,
        total_users=total_users, active_users=active_users,
        total_up=total_up, total_down=total_down, total_inbounds=total_inbounds,
        panel_name=get_setting("panel_title","XBZ PRO"),
        server_domain=get_setting("server_domain","your-domain.com"))

# ─── Settings Page ──────────────────────────────────────
@app.route("/settings", methods=["GET","POST"])
@login_required
def settings_page():
    if request.method == "POST":
        for key in ["panel_title","server_domain","server_port","sub_path"]:
            if key in request.form:
                set_setting(key, request.form[key])
        return redirect(url_for("settings_page"))
    return render_template_string(SETTINGS_HTML,
        panel_name=get_setting("panel_title","XBZ PRO"),
        domain=get_setting("server_domain"),
        port=get_setting("server_port"),
        sub_path=get_setting("sub_path"),
        title=get_setting("panel_title"))

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
    db = get_db()
    db.execute("UPDATE users_vpn SET up=0, down=0 WHERE id=?", (uid,))
    db.commit(); db.close()
    return jsonify({"success":True})

# ─── API: Generate Link ────────────────────────────────
@app.route("/api/link/<int:uid>")
@login_required
def gen_link(uid):
    db = get_db()
    u = db.execute("""SELECT u.*, i.protocol, i.port as iport, i.network, i.security,
        i.sni, i.domain, i.host, i.path, i.flow
        FROM users_vpn u JOIN inbounds i ON u.inbound_id=i.id WHERE u.id=?""", (uid,)).fetchone()
    db.close()
    if not u: return jsonify({"error":"not found"}), 404

    proto = u["protocol"]; uuid_val = u["uuid"]
    domain = u["domain"] or get_setting("server_domain","your-domain.com")
    port = u["iport"] or int(get_setting("server_port","443"))
    sni = u["sni"] or domain; host = u["host"] or domain
    path = u["path"] or "/"; net = u["network"] or "ws"
    sec = u["security"] or "none"; flow = u["flow"] or ""
    email = u["email"]

    if proto == "vless":
        p = f"host={sni}&path={path}&type={net}"
        if sec == "tls": p += f"&security=tls&sni={sni}&fp=chrome"
        if flow: p += f"&flow={flow}"
        link = f"vless://{uuid_val}@{domain}:{port}?{p}#{email}"
    elif proto == "vmess":
        obj = {"v":"2","ps":email,"add":domain,"port":str(port),"id":uuid_val,
               "aid":"0","scy":"auto","net":net,"type":"tcp","host":sni,
               "path":path,"tls":sec,"sni":sni}
        link = "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()
    elif proto == "trojan":
        link = f"trojan://{uuid_val}@{domain}:{port}?type={net}&host={sni}&path={path}&security=tls&sni={sni}#{email}"
    elif proto == "shadowsocks":
        link = f"ss://{base64.b64encode(f'chacha20-ietf-poly1305:{uuid_val}'.encode()).decode()}@{domain}:{port}#{email}"
    else:
        link = f"{proto}://unsupported"

    return jsonify({"link":link, "email":email, "uuid":uuid_val})

# ─── Subscription Endpoint ──────────────────────────────
@app.route("/sub/<token>")
def subscription(token):
    db = get_db()
    users = db.execute("""SELECT u.*, i.protocol, i.port as iport, i.network, i.security,
        i.sni, i.domain, i.host, i.path, i.flow
        FROM users_vpn u JOIN inbounds i ON u.inbound_id=i.id WHERE u.uuid=? AND u.enable=1""",
        (token,)).fetchone()
    db.close()
    if not users: return "Not Found", 404

    links = []
    domain = users["domain"] or get_setting("server_domain","your-domain.com")
    port = users["iport"] or int(get_setting("server_port","443"))
    proto = users["protocol"]; uuid_val = users["uuid"]
    sni = users["sni"] or domain; host = users["host"] or domain
    path = users["path"] or "/"; net = users["network"] or "ws"
    sec = users["security"] or "none"; flow = users["flow"] or ""
    email = users["email"]

    if proto == "vless":
        p = f"host={sni}&path={path}&type={net}"
        if sec == "tls": p += f"&security=tls&sni={sni}&fp=chrome"
        if flow: p += f"&flow={flow}"
        links.append(f"vless://{uuid_val}@{domain}:{port}?{p}#{email}")
    elif proto == "vmess":
        obj = {"v":"2","ps":email,"add":domain,"port":str(port),"id":uuid_val,
               "aid":"0","scy":"auto","net":net,"type":"tcp","host":sni,
               "path":path,"tls":sec,"sni":sni}
        links.append("vmess://" + base64.b64encode(json.dumps(obj).encode()).decode())

    return Response("\n".join(links), content_type="text/plain; charset=utf-8")

# ─── HTML Templates ─────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>XBZ PRO - Login</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden}
body::before{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,rgba(120,50,250,0.15),transparent 50%),radial-gradient(ellipse at 70% 80%,rgba(250,50,120,0.1),transparent 50%);animation:bg 8s ease-in-out infinite alternate}
@keyframes bg{0%{transform:rotate(0deg)}100%{transform:rotate(3deg)}}
.card{position:relative;z-index:1;background:rgba(255,255,255,0.03);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.08);border-radius:24px;padding:48px 40px;width:420px;text-align:center}
.logo{font-size:3em;margin-bottom:8px}
.card h1{color:#fff;font-size:1.8em;margin-bottom:4px}
.card .sub{color:#666;font-size:0.9em;margin-bottom:32px}
.field{position:relative;margin-bottom:16px}
.field input{width:100%;padding:14px 16px;border:1px solid rgba(255,255,255,0.1);border-radius:14px;background:rgba(255,255,255,0.04);color:#fff;font-size:0.95em;transition:0.3s;font-family:inherit}
.field input:focus{border-color:rgba(120,50,250,0.5);outline:none;box-shadow:0 0 20px rgba(120,50,250,0.1)}
.field input::placeholder{color:#555}
.btn{width:100%;padding:15px;background:linear-gradient(135deg,#7832fa,#fa3278);border:none;border-radius:14px;color:#fff;font-size:1.05em;font-weight:700;cursor:pointer;transition:0.3s;font-family:inherit}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(120,50,250,0.3)}
.err{color:#fa3278;margin-bottom:16px;font-size:0.85em}
</style></head><body>
<div class="card">
<div class="logo">⚡</div>
<h1>XBZ PRO</h1>
<div class="sub">پنل مدیریت VPN</div>
{% if error %}<div class="err">{{error}}</div>{% endif %}
<form method="POST">
<div class="field"><input name="username" placeholder="نام کاربری" required></div>
<div class="field"><input name="password" type="password" placeholder="رمز عبور" required></div>
<button type="submit" class="btn">ورود به پنل</button>
</form>
</div></body></html>"""

SETTINGS_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Settings - XBZ PRO</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;color:#e0e0e0;min-height:100vh}
.nav{background:rgba(255,255,255,0.02);padding:16px 32px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.06)}
.nav h2{color:#7832fa;font-size:1.3em}.nav a{color:#666;text-decoration:none;margin-right:16px;transition:0.2s}.nav a:hover{color:#fa3278}
.ct{max-width:700px;margin:40px auto;padding:0 24px}
.sec{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:20px;padding:32px}
.sec h3{color:#7832fa;margin-bottom:24px}
.fg{margin-bottom:16px}
.fg label{display:block;color:#888;font-size:0.85em;margin-bottom:6px}
.fg input{width:100%;padding:12px 16px;border:1px solid rgba(255,255,255,0.1);border-radius:12px;background:rgba(255,255,255,0.04);color:#fff;font-size:0.95em;font-family:inherit}
.fg input:focus{border-color:rgba(120,50,250,0.5);outline:none}
.btn{padding:12px 32px;background:linear-gradient(135deg,#7832fa,#fa3278);border:none;border-radius:12px;color:#fff;font-weight:700;cursor:pointer;font-family:inherit}
</style></head><body>
<div class="nav"><h2>⚙️ Settings</h2><div><a href="/">Dashboard</a><a href="/logout">خروج</a></div></div>
<div class="ct"><div class="sec"><h3>تنظیمات پنل</h3>
<form method="POST">
<div class="fg"><label>نام پنل</label><input name="panel_title" value="{{title}}"></div>
<div class="fg"><label>دامنه سرور (SNI/Domain)</label><input name="server_domain" value="{{domain}}"></div>
<div class="fg"><label>پورت سرور</label><input name="server_port" value="{{port}}"></div>
<div class="fg"><label>مسیر اشتراک</label><input name="sub_path" value="{{sub_path}}"></div>
<button type="submit" class="btn">ذخیره</button>
</form></div></div></body></html>"""

DASH_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{panel_name}}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;color:#e0e0e0;min-height:100vh}
.nav{background:rgba(255,255,255,0.02);padding:14px 32px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.06)}
.nav h2{color:#7832fa;font-size:1.3em}.nav a{color:#666;text-decoration:none;margin-right:16px;transition:0.2s;font-size:0.9em}.nav a:hover{color:#fa3278}
.ct{max-width:1200px;margin:24px auto;padding:0 24px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:16px;padding:20px;text-align:center}
.stat .num{font-size:2em;font-weight:700;background:linear-gradient(135deg,#7832fa,#fa3278);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat .label{color:#666;font-size:0.85em;margin-top:4px}
.sec{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:20px;padding:24px;margin-bottom:20px}
.sec h3{color:#7832fa;margin-bottom:16px;font-size:1.1em}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 12px;text-align:right;border-bottom:1px solid rgba(255,255,255,0.04);font-size:0.82em}
th{color:#555;font-weight:600;font-size:0.75em;text-transform:uppercase;letter-spacing:0.5px}
.badge{display:inline-block;padding:3px 10px;border-radius:8px;font-size:0.75em;font-weight:600}
.bg{background:rgba(76,175,80,0.15);color:#4caf50}.br{background:rgba(244,67,54,0.15);color:#f44336}
.bb{background:rgba(33,150,243,0.15);color:#2196f3}.bp{background:rgba(120,50,250,0.15);color:#7832fa}
.btn{padding:6px 14px;border:none;border-radius:8px;cursor:pointer;font-size:0.78em;margin:1px;transition:0.2s;font-family:inherit}
.ba{background:linear-gradient(135deg,#7832fa,#fa3278);color:#fff}.ba:hover{opacity:0.85}
.bd{background:rgba(244,67,54,0.15);color:#f44336}.bd:hover{background:rgba(244,67,54,0.3)}
.bl{background:rgba(33,150,243,0.15);color:#2196f3}.bl:hover{background:rgba(33,150,243,0.3)}
.bt{background:rgba(255,193,7,0.15);color:#ffc107}.bt:hover{background:rgba(255,193,7,0.3)}
.bgr{background:rgba(76,175,80,0.15);color:#4caf50}.bgr:hover{background:rgba(76,175,80,0.3)}
input,select{padding:8px 12px;border:1px solid rgba(255,255,255,0.1);border-radius:10px;background:rgba(255,255,255,0.04);color:#fff;font-size:0.85em;margin:3px;font-family:inherit}
input:focus,select:focus{border-color:rgba(120,50,250,0.4);outline:none}
select option{background:#1a1a2e;color:#fff}
.fr{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.copy-box{background:rgba(76,175,80,0.05);border:1px solid rgba(76,175,80,0.2);border-radius:12px;padding:14px;margin-top:10px;word-break:break-all;font-family:monospace;font-size:0.8em;color:#4caf50;display:none}
.uuid-text{font-family:monospace;font-size:0.72em;color:#888}
.traffic{font-size:0.75em;color:#888}
.modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:100;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:#1a1a2e;border:1px solid rgba(255,255,255,0.1);border-radius:20px;padding:32px;width:500px;max-height:80vh;overflow-y:auto}
.modal h3{color:#7832fa;margin-bottom:20px}
.modal .close{float:left;cursor:pointer;color:#666;font-size:1.2em}
.modal .close:hover{color:#f44336}
</style></head><body>
<div class="nav">
<h2>⚡ {{panel_name}}</h2>
<div>
<a href="/settings">⚙️ تنظیمات</a>
<a href="/logout">خروج</a>
</div>
</div>
<div class="ct">

<!-- Stats -->
<div class="stats">
<div class="stat"><div class="num">{{total_inbounds}}</div><div class="label">اینباند</div></div>
<div class="stat"><div class="num">{{total_users}}</div><div class="label">کل کاربران</div></div>
<div class="stat"><div class="num">{{active_users}}</div><div class="label">فعال</div></div>
<div class="stat"><div class="num">{{'%0.1f'|format(total_down/1073741824)}} GB</div><div class="label">دانلود کل</div></div>
</div>

<!-- Inbounds -->
<div class="sec">
<h3>📡 اینباندها</h3>
<button class="btn ba" onclick="showModal('inboundModal')" style="margin-bottom:16px">➕ اینباند جدید</button>
<table>
<tr><th>#</th><th>نام</th><th>پروتکل</th><th>پورت</th><th>Domain</th><th>SNI</th><th>شبکه</th><th>وضعیت</th><th>عملیات</th></tr>
{% for i in inbounds %}<tr>
<td>{{i.id}}</td><td style="font-weight:600">{{i.name}}</td>
<td><span class="badge bp">{{i.protocol|upper}}</span></td>
<td>{{i.port}}</td><td>{{i.domain}}</td><td>{{i.sni}}</td><td>{{i.network}}</td>
<td>{% if i.enable %}<span class="badge bg">فعال</span>{% else %}<span class="badge br">غیرفعال</span>{% endif %}</td>
<td>
<button class="btn bt" onclick="togIn({{i.id}})">🔄</button>
<button class="btn bd" onclick="delIn({{i.id}})">🗑️</button>
</td></tr>{% endfor %}
</table></div>

<!-- Users -->
<div class="sec">
<h3>👤 کاربران</h3>
<button class="btn ba" onclick="showModal('userModal')" style="margin-bottom:16px">➕ کاربر جدید</button>
<table>
<tr><th>#</th><th>نام</th><th>UUID</th><th>اینباند</th><th>ترافیک</th><th>انقضا</th><th>وضعیت</th><th>عملیات</th></tr>
{% for u in users %}<tr>
<td>{{u.id}}</td>
<td style="font-weight:600">{{u.email}}</td>
<td class="uuid-text">{{u.uuid[:16]}}...</td>
<td>{{u.inb_name or '-'}} <span class="badge bp" style="font-size:0.65em">{{u.inb_proto or ''}}</span></td>
<td class="traffic">{{'%0.2f'|format(u.up/1073741824)}}↑ / {{'%0.2f'|format(u.down/1073741824)}}↓ GB</td>
<td class="traffic">{{u.expiry//86400}} روز</td>
<td>{% if u.enable %}<span class="badge bg">فعال</span>{% else %}<span class="badge br">غیرفعال</span>{% endif %}</td>
<td>
<button class="btn bl" onclick="getL({{u.id}})">🔗 لینک</button>
<button class="btn bgr" onclick="subLink('{{u.uuid}}')">📋 اشتراک</button>
<button class="btn bt" onclick="togU({{u.id}})">🔄</button>
<button class="btn bd" onclick="delU({{u.id}})">🗑️</button>
</td></tr>{% endfor %}
</table>
<div id="lbox" class="copy-box"></div></div>

</div>

<!-- Inbound Modal -->
<div class="modal-overlay" id="inboundModal">
<div class="modal">
<span class="close" onclick="hideModal('inboundModal')">✕</span>
<h3>➕ اینباند جدید</h3>
<div class="fr"><input id="i-name" placeholder="نام اینباند" value="VLESS-NL" style="width:150px">
<select id="i-proto"><option value="vless">VLESS</option><option value="vmess">VMess</option><option value="trojan">Trojan</option></select>
<input id="i-port" placeholder="پورت" value="443" type="number" style="width:70px"></div>
<div class="fr"><input id="i-domain" placeholder="Domain (مثلاً google.com)" style="width:250px">
<input id="i-sni" placeholder="SNI (خالی = Domain)" style="width:200px"></div>
<div class="fr"><input id="i-host" placeholder="Host Header" style="width:200px">
<input id="i-path" placeholder="Path" value="/ws" style="width:100px"></div>
<div class="fr"><select id="i-net"><option value="ws">WebSocket</option><option value="grpc">gRPC</option><option value="tcp">TCP</option><option value="h2">HTTP/2</option></select>
<select id="i-sec"><option value="none">None</option><option value="tls">TLS</option></select>
<button class="btn ba" onclick="addIn()">ذخیره</button></div>
</div></div>

<!-- User Modal -->
<div class="modal-overlay" id="userModal">
<div class="modal">
<span class="close" onclick="hideModal('userModal')">✕</span>
<h3>➕ کاربر جدید</h3>
<div class="fr"><input id="u-email" placeholder="نام کاربری"></div>
<div class="fr"><select id="u-inbound">{% for i in inbounds %}<option value="{{i.id}}">{{i.name}} ({{i.protocol}}:{{i.port}})</option>{% endfor %}</select></div>
<div class="fr"><input id="u-exp" placeholder="روز (30)" type="number" value="30" style="width:80px">
<input id="u-total" placeholder="GB (0=نامحدود)" type="number" value="0" style="width:100px">
<input id="u-limitip" placeholder="محدودیت IP (0)" type="number" value="0" style="width:80px"></div>
<div class="fr"><input id="u-tgid" placeholder="Telegram ID (اختیاری)" style="width:180px">
<input id="u-comment" placeholder="توضیحات" style="width:200px"></div>
<div class="fr"><button class="btn ba" onclick="addU()">ذخیره</button></div>
</div></div>

<script>
function showModal(id){document.getElementById(id).classList.add('show')}
function hideModal(id){document.getElementById(id).classList.remove('show')}
function g(id){return document.getElementById(id).value}

function addIn(){fetch("/api/inbound/add",{method:"POST",headers:{"Content-Type":"application/json"},
body:JSON.stringify({name:g("i-name"),protocol:g("i-proto"),port:g("i-port"),domain:g("i-domain"),
sni:g("i-sni"),host:g("i-host"),path:g("i-path"),network:g("i-net"),security:g("i-sec")})
}).then(r=>r.json()).then(d=>{if(d.success)location.reload()})}

function delIn(id){if(confirm("اینباند حذف شود؟"))fetch("/api/inbound/delete/"+id,{method:"POST"}).then(()=>location.reload())}
function togIn(id){fetch("/api/inbound/toggle/"+id,{method:"POST"}).then(()=>location.reload())}

function addU(){fetch("/api/user/add",{method:"POST",headers:{"Content-Type":"application/json"},
body:JSON.stringify({email:g("u-email"),inbound_id:g("u-inbound"),expiry:g("u-exp"),
total:g("u-total"),limit_ip:g("u-limitip"),tg_id:g("u-tgid"),comment:g("u-comment")})
}).then(r=>r.json()).then(d=>{if(d.success)location.reload()})}

function delU(id){if(confirm("کاربر حذف شود؟"))fetch("/api/user/delete/"+id,{method:"POST"}).then(()=>location.reload())}
function togU(id){fetch("/api/user/toggle/"+id,{method:"POST"}).then(()=>location.reload())}

function getL(id){fetch("/api/link/"+id).then(r=>r.json()).then(d=>{
var b=document.getElementById("lbox");b.style.display="block";b.innerHTML="<strong>🔗 لینک VPN:</strong><br>"+d.link;
navigator.clipboard.writeText(d.link||"").catch(()=>{})})}

function subLink(uuid){
var url=window.location.origin+"/sub/"+uuid;
var b=document.getElementById("lbox");b.style.display="block";
b.innerHTML="<strong>📋 لینک اشتراک:</strong><br>"+url;
navigator.clipboard.writeText(url).catch(()=>{})}
</script></body></html>"""

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)
