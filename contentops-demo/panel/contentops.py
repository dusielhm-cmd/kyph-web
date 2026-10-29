"""ContentOps inside the existing panel, its cookie and its auth.sqlite volume.

No public registration, no provider calls and no publishing. Enable explicitly.
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from functools import wraps
from pathlib import Path
from flask import Blueprint, abort, jsonify, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

SCHEMA = '''
CREATE TABLE IF NOT EXISTS co_users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1 CHECK(active IN(0,1)));
CREATE TABLE IF NOT EXISTS co_sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS co_login_limits(key TEXT PRIMARY KEY,count INTEGER NOT NULL,until_time REAL NOT NULL);
CREATE TABLE IF NOT EXISTS co_scripts(id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,front TEXT NOT NULL CHECK(front IN('01','02','03')),title TEXT NOT NULL,current_version INTEGER NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS co_versions(script_id TEXT NOT NULL,version INTEGER NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,created_by TEXT NOT NULL,created_at REAL NOT NULL,PRIMARY KEY(script_id,version));
CREATE TABLE IF NOT EXISTS co_requests(id TEXT PRIMARY KEY,script_id TEXT NOT NULL,base_version INTEGER NOT NULL,message TEXT NOT NULL,state TEXT NOT NULL,created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS co_approvals(script_id TEXT NOT NULL,version INTEGER NOT NULL,digest TEXT NOT NULL,agent_id TEXT NOT NULL,created_at REAL NOT NULL,PRIMARY KEY(script_id,version));
CREATE TABLE IF NOT EXISTS co_assets(id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,script_id TEXT NOT NULL,version INTEGER NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,mime TEXT NOT NULL,bytes INTEGER NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS co_credits(job_id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,delta REAL NOT NULL,kind TEXT NOT NULL,source TEXT NOT NULL,created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS co_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,detail TEXT NOT NULL,created_at REAL NOT NULL);
'''


def register_contentops(app, db, owner_authenticated, csrf, data_dir):
    if os.environ.get('KYPH_CONTENTOPS', '0') != '1':
        return
    with db() as con:
        con.executescript(SCHEMA)
    root = Path(data_dir) / 'contentops-files'
    root.mkdir(mode=0o700, exist_ok=True)
    bp = Blueprint('contentops', __name__, url_prefix='/contentops')
    dummy_hash = generate_password_hash(secrets.token_urlsafe(32), method='scrypt')

    def sha(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def identity():
        if owner_authenticated():
            return {'id': 'OWNER', 'role': 'admin'}
        token = session.get('co_sid', '')
        if not token:
            return None
        with db() as con:
            row = con.execute('SELECT u.id FROM co_sessions s JOIN co_users u ON u.id=s.user_id WHERE s.token=? AND s.expires>? AND u.active=1', (sha(token), time.time())).fetchone()
        return {'id': row['id'], 'role': 'agent'} if row else None

    app.extensions['contentops_identity'] = identity

    def protected(admin=False):
        def outer(fn):
            @wraps(fn)
            def inner(*args, **kwargs):
                who = identity()
                if not who:
                    abort(401)
                if admin and who['role'] != 'admin':
                    abort(403)
                return fn(who, *args, **kwargs)
            return inner
        return outer

    def log(con, who, action, target, detail=''):
        con.execute('INSERT INTO co_audit(actor,action,target,detail,created_at) VALUES(?,?,?,?,?)', (who['id'], action, target, detail, time.time()))

    def begin(con):
        con.execute('BEGIN IMMEDIATE')

    def owned_script(con, who, sid):
        row = con.execute('SELECT * FROM co_scripts WHERE id=?', (sid,)).fetchone()
        if not row or (who['role'] != 'admin' and row['agent_id'] != who['id']):
            abort(404)
        return row

    def text(name, maximum=20000):
        value = request.form.get(name, '').strip()
        if not value or len(value) > maximum:
            abort(400)
        return value

    def version():
        try:
            return int(request.form.get('version', ''))
        except (ValueError, TypeError):
            abort(400)

    def render(body, **values):
        # Server-owned identity; never derive permissions from UI or form values.
        who = identity()
        display_user = ''
        if who and who['role'] == 'agent':
            with db() as con:
                user = con.execute('SELECT email FROM co_users WHERE id=?', (who['id'],)).fetchone()
                display_user = user['email'] if user else ''
        active = 'files' if request.path.startswith('/contentops/archivos') else ('credits' if request.path.startswith('/contentops/creditos') else 'scripts')
        return render_template_string('''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KYPH · ContentOps</title><style>
:root{--ink:#142f36;--muted:#526b72;--accent:#18645c;--line:#d6e3df;--paper:#f4f6f2}*{box-sizing:border-box}body{font:16px/1.55 system-ui,sans-serif;background:var(--paper);color:var(--ink);margin:0}a{color:var(--accent);text-underline-offset:4px}a:hover{text-decoration-thickness:2px}.skip{position:absolute;left:16px;top:-60px;background:white;padding:10px;z-index:2}.skip:focus{top:12px}header{background:#102f35;color:#fff}.top{max-width:1100px;margin:auto;padding:24px 32px;display:flex;gap:24px;align-items:center;justify-content:space-between}.brand{font-weight:800;font-size:24px;letter-spacing:2px}.brand small{font-size:14px;font-weight:400;letter-spacing:0;color:#d0e1dc;display:block}.identity{font-size:13px;text-align:right;overflow-wrap:anywhere}.identity p{margin:0}.identity form{margin:0}.identity button{margin:8px 0 0;padding:6px 12px;background:transparent;color:white;border:1px solid #7b9c98;font-size:13px}main{max-width:1100px;margin:auto;padding:24px 32px 48px}nav{display:flex;gap:8px;flex-wrap:wrap;padding-bottom:24px;border-bottom:1px solid var(--line);margin-bottom:30px}nav a{padding:9px 16px;border-radius:8px;text-decoration:none;font-weight:650}nav a[aria-current=page]{background:var(--ink);color:#fff}.card{background:white;border:1px solid var(--line);border-radius:16px;padding:26px;margin:20px 0;box-shadow:0 3px 10px #17363004}h1{font-size:clamp(28px,4vw,40px);line-height:1.15;letter-spacing:-1px;margin:12px 0 16px}h2{font-size:22px;line-height:1.3;margin:0 0 14px}p{margin:10px 0}.muted,.hint{color:var(--muted)}.hint{font-size:14px}.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:1.5px;font-weight:750;color:var(--accent)}label{display:block;margin:18px 0 8px;font-weight:650}input,textarea,select{width:100%;border:1px solid #8ea9a1;border-radius:8px;background:#fff;padding:12px;font:inherit;color:var(--ink)}textarea{resize:vertical;min-height:140px;line-height:1.65}input[type=checkbox]{width:20px;height:20px;margin:0 10px 0 0;vertical-align:middle;accent-color:var(--accent)}button,.button{background:var(--accent);color:white;border:1px solid transparent;border-radius:8px;padding:13px 20px;margin-top:14px;font:inherit;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block}button:hover,.button:hover{background:#124a44}a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid #a8781b;outline-offset:4px}.error{color:#a02b2b}.badge{display:inline-block;border:1px solid #b4cfbd;background:#eaf4e7;padding:4px 10px;border-radius:30px;font-size:13px;font-weight:650}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.stat{background:#fff;border:1px solid var(--line);border-radius:12px;padding:20px}.stat strong{display:block;font-size:32px;line-height:1.1;margin-bottom:10px}.step-list{display:flex;gap:8px;flex-wrap:wrap;list-style:none;padding:0;margin:24px 0}.step-list li{padding:9px 13px;border:1px solid var(--line);border-radius:8px;font-size:14px;background:#fff}.step-list li[aria-current=step]{background:var(--ink);color:white;border-color:var(--ink)}.script-current{border-top:4px solid var(--accent)}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;font-size:17px;line-height:1.8;margin:10px 0}details{margin:18px 0;background:#fff;border:1px solid var(--line);border-radius:12px;padding:18px 24px}summary{cursor:pointer;font-weight:700}.hash{font:12px ui-monospace,monospace;overflow-wrap:anywhere;color:var(--muted)}footer{border-top:1px solid var(--line);margin-top:34px;padding-top:20px;font-size:13px;color:var(--muted)}@media(max-width:600px){.top{padding:20px;align-items:flex-start;gap:12px}.brand{font-size:20px}.identity{max-width:50%}main{padding:20px}.card{padding:20px}.stats{grid-template-columns:1fr}.stat strong{font-size:28px}nav a{padding:9px 11px}.step-list{display:grid;grid-template-columns:1fr 1fr}.hash{font-size:11px}button{width:100%}.identity button{width:auto}pre{font-size:16px}}
</style></head><body><a class="skip" href="#contenido">Saltar al contenido</a><header><div class="top"><div class="brand">KYPH<small>ContentOps · Guiones y revisión</small></div>{% if ui_who %}<div class="identity"><p>{{'Administración KYPH' if ui_who.role=='admin' else 'Espacio privado del agente'}}</p>{% if display_user %}<p>{{display_user}}</p>{% endif %}<form action="/contentops/logout" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><button>Cerrar sesión</button></form></div>{% else %}<div class="identity">Acceso individual<br>Sin registro público</div>{% endif %}</div></header><main id="contenido">{% if ui_who %}<nav aria-label="Secciones de ContentOps"><a href="/contentops/" {% if active=='scripts' %}aria-current="page"{% endif %}>Mis guiones</a><a href="/contentops/archivos" {% if active=='files' %}aria-current="page"{% endif %}>Videos y portadas</a><a href="/contentops/creditos" {% if active=='credits' %}aria-current="page"{% endif %}>Mis créditos</a></nav>{% endif %}''' + body + '''<footer>Espacio privado · Solo tu material asignado.<br>Aprobar un guion permite grabarlo; no autoriza su publicación.</footer></main></body></html>''', csrf=csrf(), ui_who=who, display_user=display_user, active=active, **values)

    @bp.route('/login', methods=['GET', 'POST'])
    def login():
        if identity():
            return redirect('/contentops/')
        error = ''
        status = 200
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()[:254]
            now = time.time()
            # Per-account and global buckets. Do not trust client proxy headers as IP.
            keys = ['global', sha(email)]
            with db() as con:
                begin(con)
                limits = [con.execute('SELECT * FROM co_login_limits WHERE key=?', (key,)).fetchone() for key in keys]
                if any(row and row['until_time'] > now for row in limits):
                    abort(429)
                user = con.execute('SELECT * FROM co_users WHERE email=? AND active=1', (email,)).fetchone()
                supplied = request.form.get('password', '')[:128]
                correct = check_password_hash(user['password'] if user else dummy_hash, supplied)
                if not user or not correct:
                    for key, row in zip(keys, limits):
                        count = (row['count'] if row and row['until_time'] == 0 else 0) + 1
                        threshold = 50 if key == 'global' else 5
                        con.execute('INSERT OR REPLACE INTO co_login_limits VALUES(?,?,?)', (key, count, now + 900 if count >= threshold else 0))
                    error, status = 'No fue posible iniciar sesión con esos datos.', 401
                else:
                    token = secrets.token_urlsafe(48)
                    con.execute('DELETE FROM co_sessions WHERE expires<=?', (now,))
                    con.execute('INSERT INTO co_sessions VALUES(?,?,?)', (sha(token), user['id'], now + 7200))
                    con.execute('DELETE FROM co_login_limits WHERE key=?', (sha(email),))
                    log(con, {'id': user['id']}, 'LOGIN', user['id'])
                    session.clear()
                    session.permanent = True
                    session['co_sid'] = token
                    return redirect('/contentops/')
        return render('''<section class="card"><h1>Acceso de agentes</h1><p>Usa tu acceso individual habilitado por KYPH.</p><p class="error">{{error}}</p><form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>Correo<input name="email" type="email" autocomplete="username" required></label><label>Contraseña<input name="password" type="password" autocomplete="current-password" maxlength="128" required></label><button>Entrar</button></form><p><a href="/login">Acceso de David</a></p></section>''', error=error), status

    @bp.post('/logout')
    @protected()
    def logout(who):
        with db() as con:
            con.execute('DELETE FROM co_sessions WHERE token=?', (sha(session.get('co_sid', '')),))
            if who['role'] == 'admin':
                con.execute('DELETE FROM sessions WHERE token=?', (session.get('sid', ''),))
        session.clear()
        return redirect('/contentops/login')

    @bp.get('/')
    @protected()
    def home(who):
        with db() as con:
            rows = con.execute('SELECT * FROM co_scripts ORDER BY title' if who['role'] == 'admin' else 'SELECT * FROM co_scripts WHERE agent_id=? ORDER BY title', () if who['role'] == 'admin' else (who['id'],)).fetchall()
        return render('''<p class="eyebrow">Tu espacio de creación</p><h1>Mis guiones</h1><p class="muted">Abre un guion, pide los cambios que necesites y aprueba la versión final antes de grabar.</p><div class="stats"><div class="stat"><strong>{{review_count}}</strong>Por revisar</div><div class="stat"><strong>{{changes_count}}</strong>Con cambios solicitados</div><div class="stat"><strong>{{approved_count}}</strong>Aprobados para grabar</div></div>{% if admin %}<p><a href="/contentops/admin">Administrar guiones y accesos</a></p>{% endif %}{% for s in scripts %}<section class="card"><h2><a href="/contentops/guiones/{{s.id}}">{{s.title}}</a></h2><p>Frente {{s.front}} · V{{s.current_version}}</p><span class="badge">{{'Listo para revisar' if s.state=='PENDIENTE_APROBACION' else ('Cambios enviados a KYPH' if s.state=='CAMBIOS_SOLICITADOS' else 'Aprobado para grabar')}}</span></section>{% else %}<section class="card"><h2>Tu primer guion aparecerá aquí</h2><p>KYPH debe asignártelo. No necesitas crear una cuenta adicional ni cargar un video para empezar.</p></section>{% endfor %}''', scripts=rows, admin=who['role']=='admin',review_count=sum(r['state']=='PENDIENTE_APROBACION' for r in rows),changes_count=sum(r['state']=='CAMBIOS_SOLICITADOS' for r in rows),approved_count=sum(r['state']=='APROBADO' for r in rows))

    @bp.get('/admin')
    @protected(admin=True)
    def admin(who):
        with db() as con:
            users = con.execute('SELECT id,email,active FROM co_users ORDER BY email').fetchall()
        return render('''<h1>Guiones y accesos</h1><p>No hay registro público ni envío de invitaciones.</p><section class="card"><h2>Habilitar acceso autorizado</h2><form action="/contentops/admin/agentes" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>Correo del agente<input name="email" type="email" required></label><label>Contraseña inicial privada<input name="password" type="password" minlength="14" maxlength="128" autocomplete="new-password" required></label><button>Crear acceso</button></form></section><section class="card"><h2>Asignar guion V1</h2><form action="/contentops/admin/guiones" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>Agente<select name="agent_id">{% for u in users if u.active %}<option value="{{u.id}}">{{u.email}}</option>{% endfor %}</select></label><label>Frente<select name="front"><option value="01">01 · M40 y pensiones</option><option value="02">02 · Seguros y PPR</option><option value="03">03 · Reclutamiento</option></select></label><label>Título<input name="title" maxlength="180" required></label><label>Guion<textarea name="body" rows="8" maxlength="20000" required></textarea></label><button>Guardar V1</button></form></section>{% for u in users %}<section class="card"><strong>{{u.email}}</strong><p>{{'Activo' if u.active else 'Baja'}}</p>{% if u.active %}<form action="/contentops/admin/agentes/{{u.id}}/baja" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><button>Desactivar acceso y sesiones</button></form>{% endif %}</section>{% endfor %}''', users=users)

    @bp.post('/admin/agentes')
    @protected(admin=True)
    def create_agent(who):
        email = text('email', 254).lower()
        password = text('password', 128)
        if '@' not in email or len(password) < 14:
            abort(400)
        uid = secrets.token_hex(16)
        with db() as con:
            begin(con)
            try:
                con.execute('INSERT INTO co_users VALUES(?,?,?,1)', (uid, email, generate_password_hash(password, method='scrypt')))
            except sqlite3.IntegrityError:
                abort(409)
            log(con, who, 'AGENT_CREATED', uid)
        return jsonify(id=uid), 201

    @bp.post('/admin/agentes/<uid>/baja')
    @protected(admin=True)
    def disable_agent(who, uid):
        with db() as con:
            begin(con)
            if not con.execute('SELECT id FROM co_users WHERE id=?', (uid,)).fetchone():
                abort(404)
            con.execute('UPDATE co_users SET active=0 WHERE id=?', (uid,))
            con.execute('DELETE FROM co_sessions WHERE user_id=?', (uid,))
            log(con, who, 'AGENT_DISABLED', uid)
        return jsonify(ok=True)

    @bp.post('/admin/guiones')
    @protected(admin=True)
    def create_script(who):
        agent, front, title, body = text('agent_id', 64), text('front', 2), text('title', 180), text('body')
        if front not in ('01', '02', '03'):
            abort(400)
        sid = secrets.token_hex(16)
        with db() as con:
            begin(con)
            if not con.execute('SELECT id FROM co_users WHERE id=? AND active=1', (agent,)).fetchone():
                abort(404)
            con.execute('INSERT INTO co_scripts VALUES(?,?,?,?,1,?)', (sid, agent, front, title, 'PENDIENTE_APROBACION'))
            con.execute('INSERT INTO co_versions VALUES(?,1,?,?,?,?)', (sid, body, sha(body), who['id'], time.time()))
            log(con, who, 'V1_CREATED', sid)
        return jsonify(id=sid, version=1), 201

    @bp.get('/guiones/<sid>')
    @protected()
    def script(who, sid):
        with db() as con:
            row = owned_script(con, who, sid)
            versions = con.execute('SELECT version,body,digest,created_by,created_at FROM co_versions WHERE script_id=? ORDER BY version', (sid,)).fetchall()
            pending = con.execute("SELECT *,strftime('%Y-%m-%dT%H:%M:%SZ',created_at,'unixepoch') AS requested_at_iso FROM co_requests WHERE script_id=? ORDER BY created_at", (sid,)).fetchall()
            approvals = con.execute("SELECT a.version,a.digest,a.agent_id,a.created_at,u.email AS approver,strftime('%Y-%m-%dT%H:%M:%SZ',a.created_at,'unixepoch') AS approved_at_iso FROM co_approvals a JOIN co_users u ON u.id=a.agent_id WHERE a.script_id=? ORDER BY a.version", (sid,)).fetchall()
        if request.args.get('format') == 'json':
            return jsonify(id=row['id'], front=row['front'], state=row['state'], current_version=row['current_version'], versions=[dict(v) for v in versions], requests=[dict(v) for v in pending], approvals=[dict(v) for v in approvals])
        return render('''<a href="/contentops/">← Volver a mis guiones</a><p class="eyebrow">Guion privado · Frente {{s.front}}</p><h1>{{s.title}}</h1><p><span class="badge">V{{s.current_version}} · {{'Listo para revisar' if s.state=='PENDIENTE_APROBACION' else ('Cambios enviados a KYPH' if s.state=='CAMBIOS_SOLICITADOS' else 'Aprobado para grabar')}}</span></p><ol class="step-list" aria-label="Progreso del guion"><li>1 · V1 asignada</li><li {% if s.state=='CAMBIOS_SOLICITADOS' %}aria-current="step"{% endif %}>2 · Cambios solicitados</li><li {% if s.state=='PENDIENTE_APROBACION' %}aria-current="step"{% endif %}>3 · Revisión de V{{s.current_version}}</li><li {% if s.state=='APROBADO' %}aria-current="step"{% endif %}>4 · Aprobado para grabar</li></ol>{% if s.state=='CAMBIOS_SOLICITADOS' %}<p class="hint">Tu solicitud está guardada. KYPH preparará una nueva versión; la aprobación sigue pendiente.</p>{% elif s.state=='PENDIENTE_APROBACION' %}<p class="hint">Lee la versión actual y elige: solicitar cambios o aprobarla expresamente.</p>{% endif %}{% for v in versions %}{% if v.version==s.current_version %}<section class="card script-current"><h2>Versión actual · V{{v.version}}</h2><pre>{{v.body}}</pre></section>{% else %}<details><summary>Historial · Ver guion V{{v.version}}</summary><pre>{{v.body}}</pre></details>{% endif %}{% endfor %}{% for r in pending %}<section class="card"><h2>Cambio solicitado sobre V{{r.base_version}}</h2><p>{{'Solicitud atendida' if r.state=='RESUELTA' else 'Pendiente de revisión'}} · {{r.requested_at_iso}} (UTC)</p><pre>{{r.message}}</pre></section>{% endfor %}{% for a in approvals %}<section class="card"><h2>Aprobación expresa · V{{a.version}}</h2><p>{{a.approver}} · {{a.approved_at_iso}} (UTC)</p><p class="hint">Esta aprobación corresponde únicamente al texto de esta versión.</p><p class="hash">Huella de versión: {{a.digest}}</p></section>{% endfor %}{% if admin %}<section class="card"><h2>Preparar nueva versión</h2><form action="/contentops/admin/guiones/{{s.id}}/version" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="version" value="{{s.current_version}}"><label>Guion editable<textarea name="body" rows="10" maxlength="20000" required>{{versions[-1].body}}</textarea></label><button>Guardar versión para revisión</button></form></section>{% elif s.state != 'APROBADO' %}<section class="card"><form action="/contentops/guiones/{{s.id}}/cambios" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="version" value="{{s.current_version}}"><input type="hidden" name="request_id" value="{{nonce}}"><h2>¿Quieres ajustar el guion?</h2><p class="hint">Escribe qué parte cambiar y cómo te gustaría decirla. Tu solicitud se guardará junto a esta versión.</p><label>Tu solicitud<textarea name="message" maxlength="5000" required></textarea></label><button>Solicitar cambios</button></form>{% if s.state=='PENDIENTE_APROBACION' %}<form action="/contentops/guiones/{{s.id}}/aprobar" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="version" value="{{s.current_version}}"><input type="hidden" name="digest" value="{{versions[-1].digest}}"><label><input type="checkbox" name="confirm" value="yes" required>Apruebo este guion V{{s.current_version}} para grabar</label><p class="hint">Se guardarán tu usuario, la versión, la fecha y la huella del texto. Esta acción no publica contenido.</p><button>Aprobar esta versión</button></form>{% endif %}</section>{% else %}<p>Aprobación guardada. Esta aprobación permite grabar; no autoriza publicación.</p>{% endif %}''', s=row, versions=versions, pending=pending, approvals=approvals, admin=who['role']=='admin', nonce=secrets.token_hex(24))

    @bp.post('/guiones/<sid>/cambios')
    @protected()
    def changes(who, sid):
        if who['role'] != 'agent':
            abort(403)
        base, message, rid = version(), text('message', 5000), text('request_id', 64)
        if len(rid) < 24:
            abort(400)
        with db() as con:
            begin(con)
            row = owned_script(con, who, sid)
            existing = con.execute('SELECT * FROM co_requests WHERE id=?', (rid,)).fetchone()
            if existing:
                if existing['script_id'] == sid and existing['base_version'] == base and existing['message'] == message:
                    return redirect('/contentops/guiones/' + sid)
                abort(409)
            if row['current_version'] != base or row['state'] == 'APROBADO':
                abort(409)
            if con.execute('SELECT 1 FROM co_requests WHERE script_id=? AND state=?', (sid, 'PENDIENTE')).fetchone():
                abort(409)
            con.execute('INSERT INTO co_requests VALUES(?,?,?,?,?,?)', (rid, sid, base, message, 'PENDIENTE', time.time()))
            con.execute('UPDATE co_scripts SET state=? WHERE id=?', ('CAMBIOS_SOLICITADOS', sid))
            log(con, who, 'CHANGES_REQUESTED', sid, rid)
        return redirect('/contentops/guiones/' + sid)

    @bp.post('/admin/guiones/<sid>/version')
    @protected(admin=True)
    def save_version(who, sid):
        base, body = version(), text('body')
        with db() as con:
            begin(con)
            row = owned_script(con, who, sid)
            if row['current_version'] != base or row['state'] != 'CAMBIOS_SOLICITADOS':
                abort(409)
            con.execute('INSERT INTO co_versions VALUES(?,?,?,?,?,?)', (sid, base+1, body, sha(body), who['id'], time.time()))
            con.execute('UPDATE co_requests SET state=? WHERE script_id=? AND state=?', ('RESUELTA', sid, 'PENDIENTE'))
            con.execute('UPDATE co_scripts SET current_version=?,state=? WHERE id=?', (base+1, 'PENDIENTE_APROBACION', sid))
            log(con, who, 'VERSION_CREATED', sid, str(base+1))
        return redirect('/contentops/guiones/' + sid)

    @bp.post('/guiones/<sid>/aprobar')
    @protected()
    def approve(who, sid):
        if who['role'] != 'agent' or request.form.get('confirm') != 'yes':
            abort(403)
        base, digest = version(), text('digest', 64)
        with db() as con:
            begin(con)
            row = owned_script(con, who, sid)
            v = con.execute('SELECT digest FROM co_versions WHERE script_id=? AND version=?', (sid, base)).fetchone()
            if row['current_version'] != base or not v or not hmac.compare_digest(v['digest'], digest):
                abort(409)
            if row['state'] == 'APROBADO':
                return redirect('/contentops/guiones/' + sid)
            if row['state'] != 'PENDIENTE_APROBACION':
                abort(409)
            con.execute('INSERT INTO co_approvals VALUES(?,?,?,?,?)', (sid, base, digest, who['id'], time.time()))
            con.execute('UPDATE co_scripts SET state=? WHERE id=?', ('APROBADO', sid))
            log(con, who, 'VERSION_APPROVED', sid, str(base))
        return redirect('/contentops/guiones/' + sid)

    @bp.get('/creditos')
    @protected()
    def credits(who):
        with db() as con:
            rows = con.execute('SELECT job_id,delta,kind,source FROM co_credits WHERE agent_id=? ORDER BY created_at', (who['id'],)).fetchall()
        return render('''<h1>Mis créditos</h1><section class="card"><p>Saldo: <strong>NO CONCILIADO</strong></p><p>No hay una bolsa independiente de Descript por agente. Solo se mostrarán consumos atribuibles y verificados, sin descontar simulaciones.</p>{% for r in rows %}<p>{{r.job_id}} · {{r.delta}} · {{r.kind}} · {{r.source}}</p>{% endfor %}<p>No se ejecutan ediciones ni recargas desde esta pantalla.</p></section>''', rows=rows)

    @bp.post('/admin/consumos')
    @protected(admin=True)
    def record_usage(who):
        import math
        job, uid, source = text('job_id', 180), text('agent_id', 64), text('source', 2000)
        try:
            used = float(request.form.get('credits', ''))
        except ValueError:
            abort(400)
        if not math.isfinite(used) or used <= 0 or used > 100000 or request.form.get('verified') != 'yes':
            abort(400)
        with db() as con:
            begin(con)
            if not con.execute('SELECT id FROM co_users WHERE id=?', (uid,)).fetchone():
                abort(404)
            old = con.execute('SELECT * FROM co_credits WHERE job_id=?', (job,)).fetchone()
            if old:
                if old['agent_id'] == uid and old['delta'] == -used and old['source'] == source:
                    return jsonify(ok=True, repeated=True)
                abort(409)
            con.execute('INSERT INTO co_credits VALUES(?,?,?,?,?,?)', (job, uid, -used, 'USO_VERIFICADO_MANUAL', source, time.time()))
            log(con, who, 'USAGE_RECORDED', uid, job)
        return jsonify(ok=True), 201

    @bp.get('/archivos')
    @protected()
    def assets(who):
        with db() as con:
            rows = con.execute('SELECT id,name,kind,state,bytes FROM co_assets ORDER BY created_at' if who['role']=='admin' else 'SELECT id,name,kind,state,bytes FROM co_assets WHERE agent_id=? ORDER BY created_at', () if who['role']=='admin' else (who['id'],)).fetchall()
            scripts = con.execute('SELECT id,title,current_version FROM co_scripts WHERE state=?' + ('' if who['role']=='admin' else ' AND agent_id=?'), ('APROBADO',) if who['role']=='admin' else ('APROBADO',who['id'])).fetchall()
        enabled = os.environ.get('KYPH_CONTENTOPS_UPLOADS', '0') == '1'
        return render('''<h1>Videos y portadas</h1><p>Originales privados. No se comparten con otros agentes ni se envían a Descript.</p>{% for r in rows %}<section class="card"><strong>{{r.name}}</strong><p>{{r.kind}} · {{r.bytes}} bytes · {{r.state}}</p></section>{% endfor %}{% if enabled and scripts %}<section class="card"><form action="/contentops/archivos" method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="{{csrf}}"><label>Guion aprobado<select name="script_id">{% for s in scripts %}<option value="{{s.id}}">{{s.title}} · V{{s.current_version}}</option>{% endfor %}</select></label><label>Versión aprobada<input type="number" name="version" min="1" required></label><label>Tipo<select name="kind"><option value="video">Video original</option><option value="cover">Portada</option></select></label><label>Archivo<input type="file" name="file" accept="video/mp4,video/x-matroska,image/png,image/jpeg" required></label><label><input type="checkbox" name="consent" value="yes" required>Autorizo almacenamiento privado para mi revisión. Declaro tener los derechos del archivo.</label><button>Guardar para revisión privada</button></form></section>{% elif enabled %}<p>Primero aprueba un guion para poder cargar su video o portada.</p>{% else %}<p>Carga deshabilitada hasta verificar volumen privado, capacidad y respaldo.</p>{% endif %}''', rows=rows, enabled=enabled, scripts=scripts)

    @bp.post('/archivos')
    @protected()
    def upload(who):
        if os.environ.get('KYPH_CONTENTOPS_UPLOADS', '0') != '1':
            abort(404)
        if request.form.get('consent') != 'yes':
            abort(400)
        f = request.files.get('file')
        kind = request.form.get('kind')
        if not f or kind not in ('video', 'cover'):
            abort(400)
        sid, base = text('script_id',64), version()
        uid = secrets.token_hex(24)
        path = root / uid
        count, digest, head = 0, hashlib.sha256(), b''
        try:
            with db() as con:
                begin(con)
                script = owned_script(con,who,sid)
                if script['state']!='APROBADO' or script['current_version']!=base or not con.execute('SELECT 1 FROM co_approvals WHERE script_id=? AND version=? AND agent_id=?',(sid,base,script['agent_id'])).fetchone():
                    abort(409)
                agent_id=script['agent_id']
                used = con.execute('SELECT COALESCE(SUM(bytes),0) AS n FROM co_assets WHERE agent_id=?', (agent_id,)).fetchone()['n']
                with path.open('xb') as out:
                    os.chmod(path, 0o600)
                    while chunk := f.stream.read(65536):
                        head = (head + chunk)[:16]
                        count += len(chunk)
                        if count > 100*1024*1024 or used + count > 500*1024*1024:
                            abort(413)
                        digest.update(chunk)
                        out.write(chunk)
                video = len(head) >= 12 and (head[4:8] == b'ftyp' or head[:4] == b'\x1aE\xdf\xa3')
                picture = head.startswith(b'\x89PNG\r\n\x1a\n') or head.startswith(b'\xff\xd8\xff')
                if not count or not (video if kind == 'video' else picture):
                    abort(415)
                mime = 'application/octet-stream'
                name = Path(f.filename or 'archivo').name[:180]
                con.execute('INSERT INTO co_assets VALUES(?,?,?,?,?,?,?,?,?,?,?)', (uid, agent_id, sid, base, kind, name, mime, count, digest.hexdigest(), 'CUARENTENA', time.time()))
                log(con, who, 'PRIVATE_UPLOAD', uid, json.dumps({'consent': 'private_review_v1', 'sha256': digest.hexdigest()}))
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        # No inline download, playback, public URL, provider submission or acceptance of
        # file safety. Magic bytes are preliminary only; inspection remains pending.
        return redirect('/contentops/archivos')

    app.register_blueprint(bp)
