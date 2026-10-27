"""HTTP/server tests, synthetic users only. Not a browser or deployed E2E PASS."""
import importlib.util
import io
import json
import os
import re
import secrets
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path


class ContentOpsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.environ.update(DATA_DIR=self.temp.name, PANEL_HOST='panel.test', KYPH_CONTENTOPS='1', KYPH_CONTENTOPS_UPLOADS='1', BOOTSTRAP_TOKEN=secrets.token_urlsafe(48))
        spec = importlib.util.spec_from_file_location('panel_test_' + secrets.token_hex(8), Path(__file__).with_name('app.py'))
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.m.app.config['TESTING'] = True
        self.owner, self.a, self.b = [self.m.app.test_client() for _ in range(3)]
        self.owner_password = secrets.token_urlsafe(24)
        path = '/setup?token=' + os.environ['BOOTSTRAP_TOKEN']
        r = self.get(self.owner, path)
        self.assertEqual(self.post(self.owner, path, csrf=self.csrf(r), password=self.owner_password, confirmation=self.owner_password).status_code, 302)
        r = self.get(self.owner, '/login')
        self.assertEqual(self.post(self.owner, '/login', csrf=self.csrf(r), email=self.m.owner()['email'], password=self.owner_password).status_code, 302)
        self.agent_password = secrets.token_urlsafe(24)
        self.uid_a = self.add_agent('agent-a@example.invalid')
        self.uid_b = self.add_agent('agent-b@example.invalid')
        self.sid = self.add_script(self.uid_a)
        self.other_sid = self.add_script(self.uid_b)
        self.login_agent(self.a, 'agent-a@example.invalid')
        self.login_agent(self.b, 'agent-b@example.invalid')

    def tearDown(self):
        self.temp.cleanup()

    def get(self, client, path):
        return client.get(path, base_url='https://panel.test')

    def post(self, client, path, **data):
        return client.post(path, base_url='https://panel.test', data=data)

    def csrf(self, response):
        return re.search(r'name="csrf" value="([^"]+)"', response.text)[1]

    def current_csrf(self, client):
        with client.session_transaction(base_url='https://panel.test') as sess:
            if 'csrf' not in sess:
                sess['csrf'] = secrets.token_urlsafe(32)
            return sess['csrf']

    def add_agent(self, email):
        r = self.post(self.owner, '/contentops/admin/agentes', csrf=self.current_csrf(self.owner), email=email, password=self.agent_password)
        self.assertEqual(r.status_code, 201)
        return r.json['id']

    def add_script(self, uid):
        r = self.post(self.owner, '/contentops/admin/guiones', csrf=self.current_csrf(self.owner), agent_id=uid, front='02', title='Guion DEMO', body='V1: explica tus prioridades de protección.')
        self.assertEqual(r.status_code, 201)
        return r.json['id']

    def login_agent(self, client, email):
        r = self.get(client, '/contentops/login')
        r = self.post(client, '/contentops/login', csrf=self.csrf(r), email=email, password=self.agent_password)
        self.assertEqual(r.status_code, 302)
        self.assertIn('Secure', r.headers['Set-Cookie'])
        self.assertIn('HttpOnly', r.headers['Set-Cookie'])

    def state(self, client=None):
        return self.get(client or self.a, '/contentops/guiones/' + self.sid + '?format=json').json

    def request_change(self, rid=None):
        return self.post(self.a, f'/contentops/guiones/{self.sid}/cambios', csrf=self.current_csrf(self.a), version='1', message='Haz el inicio más directo.', request_id=rid or secrets.token_hex(24))

    def save_v2(self):
        return self.post(self.owner, f'/contentops/admin/guiones/{self.sid}/version', csrf=self.current_csrf(self.owner), version='1', body='V2: ¿Qué necesita continuidad en tu familia?')

    def test_real_login_request_version_approval_survives_new_connection_and_logout(self):
        self.assertEqual(self.request_change().status_code, 302)
        self.assertEqual(self.state()['state'], 'CAMBIOS_SOLICITADOS')
        self.assertEqual(self.save_v2().status_code, 302)
        state = self.state()
        self.assertEqual([v['version'] for v in state['versions']], [1, 2])
        self.assertEqual(state['versions'][0]['body'], 'V1: explica tus prioridades de protección.')
        digest = state['versions'][-1]['digest']
        r = self.post(self.a, f'/contentops/guiones/{self.sid}/aprobar', csrf=self.current_csrf(self.a), version='2', digest=digest, confirm='yes')
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.state()['state'], 'APROBADO')
        # Independent physical connection: data is not a browser-only variable.
        with sqlite3.connect(Path(self.temp.name)/'auth.sqlite') as con:
            self.assertEqual(con.execute('SELECT count(*) FROM co_approvals').fetchone()[0], 1)
            self.assertEqual(con.execute('SELECT digest FROM co_approvals').fetchone()[0], digest)
            self.assertEqual(con.execute('SELECT count(*) FROM co_audit WHERE target=?', (self.sid,)).fetchone()[0], 4)
        spec = importlib.util.spec_from_file_location('restarted_panel',Path(__file__).with_name('app.py'))
        restarted=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(restarted)
        fresh=restarted.app.test_client()
        cookie=self.a.get_cookie('__Host-kyph',domain='panel.test')
        fresh.set_cookie('__Host-kyph',cookie.value,domain='panel.test',secure=True)
        self.assertEqual(self.get(fresh,f'/contentops/guiones/{self.sid}?format=json').json['state'],'APROBADO')
        self.assertEqual(self.post(self.a, '/contentops/logout', csrf=self.current_csrf(self.a)).status_code, 302)
        self.assertEqual(self.get(self.a, f'/contentops/guiones/{self.sid}?format=json').status_code, 401)
        self.login_agent(self.a, 'agent-a@example.invalid')
        self.assertEqual(self.state()['approvals'][0]['version'], 2)
        self.assertEqual(self.get(self.a, f'/contentops/guiones/{self.sid}').status_code, 200)

    def test_tenant_and_owner_boundaries_even_with_forged_form_identity(self):
        self.assertNotIn(self.other_sid, self.get(self.a, '/contentops/').text)
        self.assertEqual(self.get(self.b, f'/contentops/guiones/{self.sid}?format=json').status_code, 404)
        self.assertEqual(self.post(self.b, f'/contentops/guiones/{self.sid}/cambios', csrf=self.current_csrf(self.b), version='1', message='forged', request_id=secrets.token_hex(24), agent_id=self.uid_a, role='admin').status_code, 404)
        self.assertEqual(self.post(self.a, '/contentops/admin/agentes', csrf=self.current_csrf(self.a), email='forged@example.invalid', password=self.agent_password).status_code, 403)
        self.assertEqual(self.get(self.a, '/contentops/admin').status_code, 403)
        self.assertEqual(self.get(self.owner, '/contentops/admin').status_code, 200)
        self.assertEqual(self.get(self.a, '/panel').location, '/login')
        self.assertEqual(self.get(self.a, '/mis-pendientes').location, '/login')
        self.assertEqual(self.get(self.a, '/api/pendientes').status_code, 401)

    def test_csrf_unauthenticated_and_session_revocation(self):
        anon = self.m.app.test_client()
        self.assertEqual(self.get(anon, '/contentops/').status_code, 401)
        self.assertEqual(self.post(self.a, f'/contentops/guiones/{self.sid}/cambios', version='1').status_code, 403)
        self.assertEqual(self.post(anon, '/contentops/archivos', csrf='anything').status_code, 401)
        r = self.post(self.owner, f'/contentops/admin/agentes/{self.uid_a}/baja', csrf=self.current_csrf(self.owner))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.get(self.a, '/contentops/').status_code, 401)
        self.assertEqual(self.get(self.b, '/contentops/').status_code, 200)

    def test_optimistic_version_idempotency_and_exact_approval(self):
        rid = secrets.token_hex(24)
        self.assertEqual(self.request_change(rid).status_code, 302)
        self.assertEqual(self.request_change(rid).status_code, 302)
        self.assertEqual(len(self.state()['requests']), 1)
        v1_digest = self.state()['versions'][0]['digest']
        self.assertEqual(self.post(self.a, f'/contentops/guiones/{self.sid}/aprobar', csrf=self.current_csrf(self.a), version='1', digest=v1_digest, confirm='yes').status_code, 409)
        self.assertEqual(self.save_v2().status_code, 302)
        self.assertEqual(self.save_v2().status_code, 409)
        self.assertEqual(self.request_change().status_code, 409)
        self.assertEqual(self.post(self.a, f'/contentops/guiones/{self.sid}/aprobar', csrf=self.current_csrf(self.a), version='1', digest=v1_digest, confirm='yes').status_code, 409)
        v = self.state()['versions'][-1]
        for expected in (302, 302):
            self.assertEqual(self.post(self.a, f'/contentops/guiones/{self.sid}/aprobar', csrf=self.current_csrf(self.a), version='2', digest=v['digest'], confirm='yes').status_code, expected)
        self.assertEqual(len(self.state()['approvals']), 1)

    def test_quarantined_private_upload_and_no_provider_call(self):
        digest=self.state()['versions'][0]['digest']
        self.assertEqual(self.post(self.a,f'/contentops/guiones/{self.sid}/aprobar',csrf=self.current_csrf(self.a),version='1',digest=digest,confirm='yes').status_code,302)
        # Minimal synthetic signature, not a valid final video or a real agent file.
        payload = b'\x00\x00\x00\x18ftypmp42' + b'test-only'*10
        r = self.a.post('/contentops/archivos', base_url='https://panel.test', data={'csrf':self.current_csrf(self.a), 'script_id':self.sid,'version':'1','kind':'video', 'consent':'yes', 'file':(io.BytesIO(payload),'test.mp4')})
        self.assertEqual(r.status_code, 302)
        self.assertIn('CUARENTENA', self.get(self.a, '/contentops/archivos').text)
        self.assertNotIn('test.mp4', self.get(self.b, '/contentops/archivos').text)
        files = list((Path(self.temp.name)/'contentops-files').iterdir())
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_bytes(), payload)
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        bad = self.a.post('/contentops/archivos', base_url='https://panel.test', data={'csrf':self.current_csrf(self.a), 'script_id':self.sid,'version':'1','kind':'cover', 'consent':'yes', 'file':(io.BytesIO(b'<script>fake</script>'),'bad.png')})
        self.assertEqual(bad.status_code, 415)
        self.assertEqual(len(list(files[0].parent.iterdir())), 1)
        self.assertEqual(self.get(self.a, '/contentops-files/'+files[0].name).status_code, 404)

    def test_credit_job_uniqueness_and_no_fictitious_balance(self):
        data = dict(csrf=self.current_csrf(self.owner), job_id='TEST-JOB-ONLY', agent_id=self.uid_a, credits='12.5', verified='yes', source='Synthetic test, no Descript call')
        self.assertEqual(self.post(self.owner, '/contentops/admin/consumos', **data).status_code, 201)
        self.assertEqual(self.post(self.owner, '/contentops/admin/consumos', **data).status_code, 200)
        data['agent_id'] = self.uid_b
        self.assertEqual(self.post(self.owner, '/contentops/admin/consumos', **data).status_code, 409)
        self.assertIn('NO CONCILIADO', self.get(self.a, '/contentops/creditos').text)
        self.assertNotIn('TEST-JOB-ONLY', self.get(self.b, '/contentops/creditos').text)

    def test_expired_session_and_xss_escaping(self):
        with self.m.db() as con:
            con.execute('UPDATE co_versions SET body=? WHERE script_id=? AND version=1', ('<script>alert(1)</script>', self.sid))
        page = self.get(self.a, f'/contentops/guiones/{self.sid}')
        self.assertNotIn('<script>alert(1)</script>', page.text)
        self.assertIn('&lt;script&gt;', page.text)
        with self.m.db() as con:
            con.execute('UPDATE co_sessions SET expires=? WHERE user_id=?', (time.time()-1, self.uid_a))
        self.assertEqual(self.get(self.a, '/contentops/').status_code, 401)

    def test_login_limit_does_not_leak_account_or_affect_owner(self):
        c = self.m.app.test_client()
        for _ in range(5):
            r = self.get(c, '/contentops/login')
            self.assertEqual(self.post(c, '/contentops/login', csrf=self.csrf(r), email='missing@example.invalid', password='wrong').status_code, 401)
        r = self.get(c, '/contentops/login')
        self.assertEqual(self.post(c, '/contentops/login', csrf=self.csrf(r), email='missing@example.invalid', password='wrong').status_code, 429)
        self.assertEqual(self.get(self.owner, '/panel').status_code, 200)


if __name__ == '__main__':
    unittest.main()
