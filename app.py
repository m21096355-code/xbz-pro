import os, json, uuid, sqlite3, secrets, base64, time
from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify, Response
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_USER = os.environ.get("ADMIN_USER", "xbz")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "xbz2026")
DB = "xbz.db"
VERSION = "1.5"

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
    c.execute("""CREATE TABLE IF NOT EXISTS traffic_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, up INTEGER DEFAULT 0,
        down INTEGER DEFAULT 0, logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    for k, v in [("panel_title","XBZ PRO"),("server_domain","your-domain.com"),
                  ("server_port","443"),("sub_path","/sub"),("sub_secret","")]:
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
    # expired count
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
               "aid":"0","scy":"auto","net":net,"type":"tcp","host":sni,
               "path":path,"tls":sec,"sni":sni}
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
    link = build_link(u, inb)
    return jsonify({"link":link, "email":u["email"], "uuid":u["uuid"]})

# ─── Subscription (v2rayNG / Hiddify / Nekobox) ────────
@app.route("/sub/<token>")
def subscription(token):
    db = get_db()
    user = db.execute("SELECT * FROM users_vpn WHERE uuid=? AND enable=1", (token,)).fetchone()
    if not user: db.close(); return "Not Found", 404

    db.execute("UPDATE users_vpn SET last_login=? WHERE id=?", (datetime.now().isoformat(), user["id"]))
    db.commit()

    inbounds = db.execute("SELECT * FROM inbounds WHERE enable=1").fetchall()
    db.close()

    links = []
    for inb in inbounds:
        if not inb["enable"]: continue
        links.append(build_link(user, inb))

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

# ─── User Info API (for clients) ───────────────────────
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

# ─── Share Page (public) ────────────────────────────────
@app.route("/share/<token>")
def share_page(token):
    db = get_db()
    user = db.execute("""SELECT u.*, i.name as inb_name, i.protocol, i.port as inb_port,
        i.domain, i.sni, i.network, i.security, i.path, i.host, i.flow
        FROM users_vpn u JOIN inbounds i ON u.inbound_id=i.id WHERE u.uuid=?""", (token,)).fetchone()
    if not user: db.close(); return "Not Found", 404
    link = build_link(user, user)
    exp = int(user['expiry']+time.time()) if user['expiry'] else 0
    exp_str = datetime.fromtimestamp(exp).strftime("%Y/%m/%d") if exp else "نامحدود"
    dn = f"{user['down']/1073741824:.2f} GB"
    tn = f"{user['total']/1073741824:.2f} GB" if user['total'] else "نامحدود"
    sub_url = f"{request.host_url}sub/{token}"
    info_url = f"{request.host_url}sub/{token}/info"
    db.close()
    return render_template_string(SHARE_HTML, link=link, email=user["email"],
        uuid=user["uuid"], protocol=user["protocol"].upper(),
        domain=user["domain"], port=user["port"],
        exp_str=exp_str, traffic_str=dn, total_str=tn, sub_url=sub_url,
        info_url=info_url, enable=user["enable"], panel_name=gs("panel_title"))

# ─── Batch User Creation ───────────────────────────────
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

# ─── Export/Import ──────────────────────────────────────
@app.route("/api/export")
@login_required
def export_data():
    db = get_db()
    inbounds = [dict(r) for r in db.execute("SELECT * FROM inbounds").fetchall()]
    users = [dict(r) for r in db.execute("SELECT * FROM users_vpn").fetchall()]
    settings = {r["key"]:r["value"] for r in db.execute("SELECT * FROM settings").fetchall()}
    db.close()
    return jsonify({"inbounds":inbounds,"users":users,"settings":settings,"version":VERSION})

# ─── HTML Templates ─────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>XBZ PRO v1.5</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden}
body::before{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,rgba(120,50,250,0.15),transparent 50%),radial-gradient(ellipse at 70% 80%,rgba(250,50,120,0.1),transparent 50%);animation:bg 8s ease-in-out infinite alternate}
@keyframes bg{0%{transform:rotate(0deg)}100%{transform:rotate(3deg)}}
.card{position:relative;z-index:1;background:rgba(255,255,255,0.03);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.08);border-radius:24px;padding:48px 40px;width:420px;text-align:center}
.logo{font-size:3.5em;margin-bottom:8px}
.card h1{color:#fff;font-size:2em;margin-bottom:2px}
.ver{color:#7832fa;font-size:0.8em;font-weight:600;margin-bottom:4px}
.card .sub{color:#555;font-size:0.9em;margin-bottom:32px}
.field input{width:100%;padding:14px 16px;border:1px solid rgba(255,255,255,0.1);border-radius:14px;background:rgba(255,255,255,0.04);color:#fff;font-size:0.95em;transition:0.3s;font-family:inherit;margin-bottom:14px}
.field input:focus{border-color:rgba(120,50,250,0.5);outline:none;box-shadow:0 0 20px rgba(120,50,250,0.1)}
.field input::placeholder{color:#444}
.btn{width:100%;padding:15px;background:linear-gradient(135deg,#7832fa,#fa3278);border:none;border-radius:14px;color:#fff;font-size:1.05em;font-weight:700;cursor:pointer;transition:0.3s;font-family:inherit}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(120,50,250,0.3)}
.err{color:#fa3278;margin-bottom:16px;font-size:0.85em}
</style></head><body>
<div class="card"><div class="logo">⚡</div><h1>XBZ PRO</h1>
<div class="ver">v1.5</div><div class="sub">پنل مدیریت VPN</div>
{% if error %}<div class="err">{{error}}</div>{% endif %}
<form method="POST">
<div class="field"><input name="username" placeholder="نام کاربری" required></div>
<div class="field"><input name="password" type="password" placeholder="رمز عبور" required></div>
<button type="submit" class="btn">ورود به پنل</button></form></div></body></html>"""

SETTINGS_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Settings</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;color:#e0e0e0;min-height:100vh}
.nav{background:rgba(255,255,255,0.02);padding:16px 32px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.06)}
.nav h2{color:#7832fa;font-size:1.3em}.nav a{color:#555;text-decoration:none;margin-right:16px;font-size:0.9em;transition:0.2s}.nav a:hover{color:#fa3278}
.ct{max-width:700px;margin:40px auto;padding:0 24px}
.sec{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:20px;padding:32px}
.sec h3{color:#7832fa;margin-bottom:24px}
.fg{margin-bottom:16px}.fg label{display:block;color:#666;font-size:0.82em;margin-bottom:6px}
.fg input{width:100%;padding:12px 16px;border:1px solid rgba(255,255,255,0.1);border-radius:12px;background:rgba(255,255,255,0.04);color:#fff;font-size:0.95em;font-family:inherit}
.fg input:focus{border-color:rgba(120,50,250,0.5);outline:none}
.btn{padding:12px 32px;background:linear-gradient(135deg,#7832fa,#fa3278);border:none;border-radius:12px;color:#fff;font-weight:700;cursor:pointer;font-family:inherit}
.info{background:rgba(120,50,250,0.08);border:1px solid rgba(120,50,250,0.2);border-radius:12px;padding:16px;margin-top:20px;font-size:0.85em;color:#aaa;line-height:2}
.info code{color:#7832fa;background:rgba(120,50,250,0.1);padding:2px 8px;border-radius:6px;font-size:0.9em}
</style></head><body>
<div class="nav"><h2>⚙️ Settings <span style="color:#444;font-size:0.7em">v{{version}}</span></h2>
<div><a href="/">داشبورد</a><a href="/logout">خروج</a></div></div>
<div class="ct"><div class="sec"><h3>تنظیمات پنل</h3>
<form method="POST">
<div class="fg"><label>نام پنل</label><input name="panel_title" value="{{title}}"></div>
<div class="fg"><label>دامنه سرور</label><input name="server_domain" value="{{domain}}"></div>
<div class="fg"><label>پورت سرور</label><input name="server_port" value="{{port}}"></div>
<div class="fg"><label>مسیر اشتراک</label><input name="sub_path" value="{{sub_path}}"></div>
<button type="submit" class="btn">💾 ذخیره</button></form>
<div class="info">
<strong>📌 لینک اشتراک:</strong><br><code>{{domain}}:{{port}}{{sub_path}}/{UUID}</code><br>
<strong>📌 صفحه اشتراک:</strong><br><code>{{domain}}:{{port}}/share/{UUID}</code><br>
<strong>📌 اطلاعات ساب:</strong><br><code>{{domain}}:{{port}}{{sub_path}}/{UUID}/info</code><br>
<strong>📌 خروجی JSON:</strong><br><code>{{domain}}:{{port}}/api/export</code><br>
<strong>📌 سازگار با:</strong> v2rayNG, Hiddify, Nekobox, V2Box, Streisand, Sing-box
</div></div></div></body></html>"""

SHARE_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{email}} - {{panel_name}}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
body::before{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,rgba(120,50,250,0.12),transparent 50%),radial-gradient(ellipse at 70% 80%,rgba(250,50,120,0.08),transparent 50%)}
.card{position:relative;z-index:1;background:rgba(255,255,255,0.03);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.08);border-radius:24px;padding:36px;width:480px;max-width:100%}
.logo{font-size:2.5em;margin-bottom:6px}.card h1{color:#fff;font-size:1.4em;margin-bottom:2px}
.card .sub{color:#555;font-size:0.85em;margin-bottom:20px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:20px;text-align:right}
.item{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.06);border-radius:12px;padding:12px}
.item .lbl{color:#555;font-size:0.72em;margin-bottom:3px}.item .val{color:#fff;font-size:0.9em;font-weight:600}
.link-box{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:12px;word-break:break-all;font-family:monospace;font-size:0.72em;color:#4caf50;margin-bottom:14px;text-align:left;direction:ltr;max-height:100px;overflow-y:auto}
.btn{width:100%;padding:13px;background:linear-gradient(135deg,#7832fa,#fa3278);border:none;border-radius:14px;color:#fff;font-size:0.95em;font-weight:700;cursor:pointer;transition:0.3s;font-family:inherit;margin-bottom:8px}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(120,50,250,0.3)}
.btn2{width:100%;padding:11px;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);border-radius:12px;color:#888;font-size:0.88em;cursor:pointer;margin-bottom:8px;font-family:inherit;transition:0.2s}
.btn2:hover{background:rgba(255,255,255,0.1);color:#fff}
.badge{display:inline-block;padding:3px 10px;border-radius:8px;font-size:0.72em;font-weight:600}
.bg{background:rgba(76,175,80,0.15);color:#4caf50}.br{background:rgba(244,67,54,0.15);color:#f44336}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#7832fa;color:#fff;padding:12px 24px;border-radius:12px;font-size:0.9em;display:none;z-index:100}
</style></head><body>
<div class="card"><div class="logo">⚡</div><h1>{{panel_name}}</h1><div class="sub">{{email}}</div>
<div class="grid">
<div class="item"><div class="lbl">پروتکل</div><div class="val">{{protocol}}</div></div>
<div class="item"><div class="lbl">وضعیت</div><div class="val">{% if enable %}<span class="badge bg">فعال</span>{% else %}<span class="badge br">غیرفعال</span>{% endif %}</div></div>
<div class="item"><div class="lbl">دامنه</div><div class="val" style="font-size:0.78em">{{domain}}</div></div>
<div class="item"><div class="lbl">پورت</div><div class="val">{{port}}</div></div>
<div class="item"><div class="lbl">ترافیک مصرفی</div><div class="val">{{traffic_str}}</div></div>
<div class="item"><div class="lbl">حجم کل</div><div class="val">{{total_str}}</div></div>
<div class="item"><div class="lbl">تاریخ انقضا</div><div class="val">{{exp_str}}</div></div>
<div class="item"><div class="lbl">UUID</div><div class="val" style="font-size:0.68em;font-family:monospace">{{uuid[:16]}}...</div></div>
</div>
<div class="link-box" id="link">{{link}}</div>
<button class="btn" onclick="copyL()">📋 کپی لینک VPN</button>
<button class="btn2" onclick="copyS()">🔗 کپی لینک اشتراک</button>
<button class="btn2" onclick="copyI()">📊 کپی لینک اطلاعات</button>
</div>
<div class="toast" id="toast">✅ کopy شد!</div>
<script>
function copyL(){navigator.clipboard.writeText(document.getElementById('link').innerText).then(()=>showT())}
function copyS(){navigator.clipboard.writeText('{{sub_url}}').then(()=>showT())}
function copyI(){navigator.clipboard.writeText('{{info_url}}').then(()=>showT())}
function showT(){var t=document.getElementById('toast');t.style.display='block';setTimeout(()=>t.style.display='none',2000)}
</script></body></html>"""

DASH_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{panel_name}} v{{version}}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;color:#e0e0e0;min-height:100vh}
.nav{background:rgba(255,255,255,0.02);padding:14px 32px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.06)}
.nav h2{color:#7832fa;font-size:1.3em}.nav a{color:#555;text-decoration:none;margin-right:16px;font-size:0.88em;transition:0.2s}.nav a:hover{color:#fa3278}
.ct{max-width:1200px;margin:24px auto;padding:0 24px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}
.stat{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:16px;padding:18px;text-align:center}
.stat .num{font-size:1.7em;font-weight:800;background:linear-gradient(135deg,#7832fa,#fa3278);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat .label{color:#555;font-size:0.78em;margin-top:4px}
.sec{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:20px;padding:24px;margin-bottom:20px}
.sec h3{color:#7832fa;margin-bottom:16px;font-size:1.05em}
table{width:100%;border-collapse:collapse}
th,td{padding:9px 10px;text-align:right;border-bottom:1px solid rgba(255,255,255,0.04);font-size:0.8em}
th{color:#444;font-weight:600;font-size:0.72em;text-transform:uppercase;letter-spacing:0.5px}
.badge{display:inline-block;padding:3px 10px;border-radius:8px;font-size:0.72em;font-weight:600}
.bg{background:rgba(76,175,80,0.15);color:#4caf50}.br{background:rgba(244,67,54,0.15);color:#f44336}
.bb{background:rgba(33,150,243,0.15);color:#2196f3}.bp{background:rgba(120,50,250,0.15);color:#7832fa}
.bor{background:rgba(255,152,0,0.15);color:#ff9800}
.btn{padding:5px 12px;border:none;border-radius:8px;cursor:pointer;font-size:0.75em;margin:1px;transition:0.2s;font-family:inherit}
.ba{background:linear-gradient(135deg,#7832fa,#fa3278);color:#fff}.ba:hover{opacity:0.85}
.bd{background:rgba(244,67,54,0.15);color:#f44336}.bd:hover{background:rgba(244,67,54,0.3)}
.bl{background:rgba(33,150,243,0.15);color:#2196f3}.bl:hover{background:rgba(33,150,243,0.3)}
.bt{background:rgba(255,193,7,0.15);color:#ffc107}
.bgr{background:rgba(76,175,80,0.15);color:#4caf50}
.bsh{background:rgba(120,50,250,0.12);color:#7832fa}.bsh:hover{background:rgba(120,50,250,0.25)}
.binfo{background:rgba(0,188,212,0.12);color:#00bcd4}.binfo:hover{background:rgba(0,188,212,0.25)}
input,select{padding:7px 11px;border:1px solid rgba(255,255,255,0.1);border-radius:10px;background:rgba(255,255,255,0.04);color:#fff;font-size:0.82em;margin:3px;font-family:inherit}
input:focus,select:focus{border-color:rgba(120,50,250,0.4);outline:none}
select option{background:#1a1a2e;color:#fff}
.fr{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.cb{background:rgba(76,175,80,0.05);border:1px solid rgba(76,175,80,0.2);border-radius:12px;padding:14px;margin-top:10px;word-break:break-all;font-family:monospace;font-size:0.78em;color:#4caf50;display:none}
.uuid-text{font-family:monospace;font-size:0.7em;color:#666}.traffic{font-size:0.73em;color:#777}
.mo{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:100;align-items:center;justify-content:center}
.mo.show{display:flex}
.md{background:#141420;border:1px solid rgba(255,255,255,0.08);border-radius:20px;padding:32px;width:520px;max-height:85vh;overflow-y:auto}
.md h3{color:#7832fa;margin-bottom:20px}
.md .cl{float:left;cursor:pointer;color:#555;font-size:1.2em;transition:0.2s}.md .cl:hover{color:#f44336}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#7832fa;color:#fff;padding:12px 24px;border-radius:12px;font-size:0.9em;display:none;z-index:200}
.info-panel{background:rgba(0,188,212,0.05);border:1px solid rgba(0,188,212,0.15);border-radius:12px;padding:16px;margin-top:10px;display:none;font-size:0.82em;line-height:1.8}
.info-panel .iplbl{color:#555}.info-panel .ipval{color:#00bcd4;font-weight:600}
</style></head><body>
<div class="nav"><h2>⚡ {{panel_name}} <span style="color:#444;font-size:0.6em">v{{version}}</span></h2>
<div><a href="/settings">⚙️ تنظیمات</a><a href="/api/export" target="_blank">📦 خروجی</a><a href="/logout">خروج</a></div></div>
<div class="ct">
<div class="stats">
<div class="stat"><div class="num">{{total_inbounds}}</div><div class="label">اینباند</div></div>
<div class="stat"><div class="num">{{total_users}}</div><div class="label">کل کاربران</div></div>
<div class="stat"><div class="num">{{active_users}}</div><div class="label">فعال</div></div>
<div class="stat"><div class="num">{{expired_users}}</div><div class="label">منقضی</div></div>
<div class="stat"><div class="num">{{'%0.1f'|format(total_down/1073741824)}} GB</div><div class="label">دانلود کل</div></div>
</div>

<div class="sec"><h3>📡 اینباندها</h3>
<button class="btn ba" onclick="showM('inM')" style="margin-bottom:14px">➕ اینباند جدید</button>
<table><tr><th>#</th><th>نام</th><th>پروتکل</th><th>پورت</th><th>Domain</th><th>SNI</th><th>شبکه</th><th>وضعیت</th><th>عملیات</th></tr>
{% for i in inbounds %}<tr>
<td>{{i.id}}</td><td style="font-weight:600">{{i.name}}</td>
<td><span class="badge bp">{{i.protocol|upper}}</span></td>
<td>{{i.port}}</td><td>{{i.domain}}</td><td>{{i.sni}}</td><td>{{i.network}}</td>
<td>{% if i.enable %}<span class="badge bg">فعال</span>{% else %}<span class="badge br">غیرفعال</span>{% endif %}</td>
<td><button class="btn bt" onclick="togIn({{i.id}})">🔄</button>
<button class="btn bd" onclick="delIn({{i.id}})">🗑️</button></td></tr>{% endfor %}
</table></div>

<div class="sec"><h3>👤 کاربران</h3>
<div class="fr" style="margin-bottom:14px">
<button class="btn ba" onclick="showM('usM')">➕ کاربر جدید</button>
<button class="btn ba" onclick="showM('batchM')" style="background:linear-gradient(135deg,#00bcd4,#7832fa)">📦 ساخت گروهی</button>
</div>
<table><tr><th>#</th><th>نام</th><th>UUID</th><th>اینباند</th><th>ترافیک</th><th>انقضا</th><th>وضعیت</th><th>عملیات</th></tr>
{% for u in users %}<tr>
<td>{{u.id}}</td><td style="font-weight:600">{{u.email}}</td>
<td class="uuid-text">{{u.uuid[:16]}}...</td>
<td>{{u.inb_name or '-'}} <span class="badge bp" style="font-size:0.6em">{{u.inb_proto or ''}}</span></td>
<td class="traffic">{{'%0.2f'|format(u.up/1073741824)}}↑ / {{'%0.2f'|format(u.down/1073741824)}}↓ GB</td>
<td class="traffic">{{u.expiry//86400}} روز</td>
<td>{% if u.enable %}<span class="badge bg">فعال</span>{% else %}<span class="badge br">غیرفعال</span>{% endif %}</td>
<td>
<button class="btn bl" onclick="getL({{u.id}})">🔗 لینک</button>
<button class="btn bsh" onclick="shareP('{{u.uuid}}')">👁️ صفحه</button>
<button class="btn binfo" onclick="showInfo({{u.id}})">📊 اطلاعات</button>
<button class="btn bt" onclick="togU({{u.id}})">🔄</button>
<button class="btn bd" onclick="delU({{u.id}})">🗑️</button>
</td></tr>{% endfor %}
</table>
<div id="lbox" class="cb"></div>
<div id="infoPanel" class="info-panel"></div>
</div>
</div>

<!-- Inbound Modal -->
<div class="mo" id="inM"><div class="md"><span class="cl" onclick="hideM('inM')">✕</span>
<h3>➕ اینباند جدید</h3>
<div class="fr"><input id="i-name" placeholder="نام" value="VLESS-NL" style="width:140px">
<select id="i-proto"><option value="vless">VLESS</option><option value="vmess">VMess</option><option value="trojan">Trojan</option></select>
<input id="i-port" placeholder="پورت" value="443" type="number" style="width:65px"></div>
<div class="fr"><input id="i-domain" placeholder="Domain" style="width:230px">
<input id="i-sni" placeholder="SNI" style="width:180px"></div>
<div class="fr"><input id="i-host" placeholder="Host" style="width:180px">
<input id="i-path" placeholder="Path" value="/ws" style="width:90px"></div>
<div class="fr"><select id="i-net"><option value="ws">WebSocket</option><option value="grpc">gRPC</option><option value="tcp">TCP</option></select>
<select id="i-sec"><option value="none">None</option><option value="tls">TLS</option></select>
<button class="btn ba" onclick="addIn()">ذخیره</button></div></div></div>

<!-- User Modal -->
<div class="mo" id="usM"><div class="md"><span class="cl" onclick="hideM('usM')">✕</span>
<h3>➕ کاربر جدید</h3>
<div class="fr"><input id="u-email" placeholder="نام کاربری" style="width:200px"></div>
<div class="fr"><select id="u-inbound" style="width:100%">{% for i in inbounds %}<option value="{{i.id}}">{{i.name}} ({{i.protocol}}:{{i.port}})</option>{% endfor %}</select></div>
<div class="fr"><input id="u-exp" placeholder="روز" type="number" value="30" style="width:70px">
<input id="u-total" placeholder="GB" type="number" value="0" style="width:80px">
<input id="u-limitip" placeholder="محدودیت IP" type="number" value="0" style="width:80px"></div>
<div class="fr"><input id="u-tgid" placeholder="Telegram ID" style="width:150px">
<input id="u-comment" placeholder="توضیحات" style="width:170px"></div>
<div class="fr"><button class="btn ba" onclick="addU()">ذخیره</button></div></div></div>

<!-- Batch Modal -->
<div class="mo" id="batchM"><div class="md"><span class="cl" onclick="hideM('batchM')">✕</span>
<h3>📦 ساخت گروهی کاربر</h3>
<div class="fr"><input id="b-count" placeholder="تعداد" type="number" value="10" style="width:80px">
<input id="b-prefix" placeholder="پیشوند نام" value="user" style="width:120px"></div>
<div class="fr"><select id="b-inbound" style="width:100%">{% for i in inbounds %}<option value="{{i.id}}">{{i.name}} ({{i.protocol}}:{{i.port}})</option>{% endfor %}</select></div>
<div class="fr"><input id="b-exp" placeholder="روز" type="number" value="30" style="width:70px">
<input id="b-total" placeholder="GB" type="number" value="0" style="width:80px"></div>
<div class="fr"><button class="btn ba" onclick="batchAdd()">📦 ساختن</button></div>
<div id="batchResult" style="margin-top:12px;font-size:0.82em;color:#4caf50"></div></div></div>

<div class="toast" id="toast">✅ کپی شد!</div>

<script>
function showM(id){document.getElementById(id).classList.add('show')}
function hideM(id){document.getElementById(id).classList.remove('show')}
function g(id){return document.getElementById(id).value}
function toast(){var t=document.getElementById('toast');t.style.display='block';setTimeout(()=>t.style.display='none',2000)}

function addIn(){fetch("/api/inbound/add",{method:"POST",headers:{"Content-Type":"application/json"},
body:JSON.stringify({name:g("i-name"),protocol:g("i-proto"),port:g("i-port"),domain:g("i-domain"),
sni:g("i-sni"),host:g("i-host"),path:g("i-path"),network:g("i-net"),security:g("i-sec")})
}).then(r=>r.json()).then(d=>{if(d.success)location.reload()})}
function delIn(id){if(confirm("حذف شود؟"))fetch("/api/inbound/delete/"+id,{method:"POST"}).then(()=>location.reload())}
function togIn(id){fetch("/api/inbound/toggle/"+id,{method:"POST"}).then(()=>location.reload())}

function addU(){fetch("/api/user/add",{method:"POST",headers:{"Content-Type":"application/json"},
body:JSON.stringify({email:g("u-email"),inbound_id:g("u-inbound"),expiry:g("u-exp"),
total:g("u-total"),limit_ip:g("u-limitip"),tg_id:g("u-tgid"),comment:g("u-comment")})
}).then(r=>r.json()).then(d=>{if(d.success)location.reload()})}
function delU(id){if(confirm("حذف شود؟"))fetch("/api/user/delete/"+id,{method:"POST"}).then(()=>location.reload())}
function togU(id){fetch("/api/user/toggle/"+id,{method:"POST"}).then(()=>location.reload())}

function getL(id){fetch("/api/link/"+id).then(r=>r.json()).then(d=>{
var b=document.getElementById("lbox");b.style.display="block";
b.innerHTML="<strong>🔗 لینک VPN:</strong><br>"+d.link+"<br><br>"+
"<strong>📋 لینک اشتراک:</strong><br>"+window.location.origin+"/sub/"+d.uuid+"<br><br>"+
"<strong>📊 اطلاعات:</strong><br>"+window.location.origin+"/sub/"+d.uuid+"/info";
navigator.clipboard.writeText(d.link||"").then(()=>toast())})}

function shareP(uuid){window.open("/share/"+uuid,"_blank")}

function showInfo(id){fetch("/api/user/info/"+id).then(r=>r.json()).then(d=>{
var p=document.getElementById("infoPanel");p.style.display="block";
p.innerHTML="<strong>📊 اطلاعات کاربر:</strong><br>"+
"<span class='iplbl'>نام:</span> <span class='ipval'>"+d.email+"</span><br>"+
"<span class='iplbl'>UUID:</span> <span class='ipval'>"+d.uuid+"</span><br>"+
"<span class='iplbl'>پروتکل:</span> <span class='ipval'>"+d.protocol+"</span><br>"+
"<span class='iplbl'>دامنه:</span> <span class='ipval'>"+d.domain+"</span><br>"+
"<span class='iplbl'>آپلود:</span> <span class='ipval'>"+d.traffic_up+"</span><br>"+
"<span class='iplbl'>دانلود:</span> <span class='ipval'>"+d.traffic_down+"</span><br>"+
"<span class='iplbl'>حجم کل:</span> <span class='ipval'>"+d.traffic_total+"</span><br>"+
"<span class='iplbl'>انقضا:</span> <span class='ipval'>"+d.expiry_date+"</span><br>"+
"<span class='iplbl'>آخرین ورود:</span> <span class='ipval'>"+(d.last_login||'هیچوقت')+"</span><br>"+
"<span class='iplbl'>لینک ساب:</span> <span class='ipval'>"+window.location.origin+"/sub/"+d.uuid+"</span>";
window.scrollTo({top:p.offsetTop-100,behavior:'smooth'})})}

function batchAdd(){fetch("/api/user/batch",{method:"POST",headers:{"Content-Type":"application/json"},
body:JSON.stringify({count:g("b-count"),prefix:g("b-prefix"),inbound_id:g("b-inbound"),
expiry:g("b-exp"),total:g("b-total")})
}).then(r=>r.json()).then(d=>{
if(d.success){
var r=document.getElementById("batchResult");
r.innerHTML="✅ "+d.count+" کاربر ساخته شد!<br><br>";
d.users.forEach(u=>{r.innerHTML+="<code>"+u.email+"</code> → <code style='color:#7832fa'>"+u.uuid+"</code><br>"});
r.innerHTML+="<br><button class='btn ba' onclick='location.reload()'>بازخوانی</button>"}})}
</script></body></html>"""

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)
