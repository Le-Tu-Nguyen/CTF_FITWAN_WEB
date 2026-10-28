"""Kiểm thử tích hợp: python -m unittest -v"""
import os
import tempfile
import time
import unittest

from app import app, db
from werkzeug.security import generate_password_hash


class Flow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        app.config.update(TESTING=True, DATABASE=os.path.join(self.tmp.name, 'test.db'))
        self.client = app.test_client()
        result = app.test_cli_runner().invoke(args=['init-db'])
        self.assertEqual(result.exit_code, 0, result.output)
        with app.app_context(), db():
            db().execute(
                'INSERT INTO users(username,password,admin) VALUES(?,?,1)',
                ('admin', generate_password_hash('admin-password')),
            )
        self.token = 'a' * 64

    def tearDown(self):
        self.tmp.cleanup()

    def post(self, url, **values):
        with self.client.session_transaction() as s:
            s['csrf'] = self.token
        return self.client.post(url, data={'csrf': self.token, **values})

    def login(self, name='admin', password='admin-password'):
        return self.post('/login', username=name, password=password)

    def test_full_flow(self):
        self.assertEqual(self.client.post('/register').status_code, 400)
        self.assertEqual(
            self.post('/register', username='player', password='long-password').status_code,
            302,
        )
        self.login()
        self.assertEqual(
            self.post(
                '/admin',
                action='challenge',
                cid=0,
                title='Test',
                category='Web',
                description='<script>alert(1)</script>',
                hint='hint',
                points=100,
                visible='on',
                flag='CTF{test}',
            ).status_code,
            302,
        )
        self.post('/logout')
        self.login('player', 'long-password')
        self.assertEqual(self.client.get('/admin').status_code, 403)
        detail = self.client.get('/challenge/1').get_data(as_text=True)
        self.assertIn('&lt;script&gt;', detail)
        self.assertNotIn('CTF{test}', detail)
        self.post('/challenge/1', flag='wrong')
        self.post('/challenge/1', flag='CTF{test}')
        self.post('/challenge/1', flag='CTF{test}')
        with app.app_context():
            self.assertEqual(db().execute('SELECT SUM(points) FROM solves').fetchone()[0], 100)
            self.assertEqual(db().execute('SELECT COUNT(*) FROM submissions').fetchone()[0], 2)
        for url in ('/', '/challenges', '/scoreboard', '/profile'):
            self.assertEqual(self.client.get(url).status_code, 200)
        with app.app_context(), db():
            db().execute(
                'UPDATE contest SET start=?,end=?',
                (int(time.time()) - 10, int(time.time()) - 1),
            )
        self.assertEqual(self.post('/challenge/1', flag='CTF{test}').status_code, 403)

    def test_hidden_time_and_limit(self):
        app.test_cli_runner().invoke(args=['seed-demo'])
        self.login()
        self.assertEqual(self.client.get('/admin').status_code, 200)
        self.assertEqual(self.post('/challenge/1', flag='x').status_code, 403)
        with app.app_context(), db():
            db().execute('UPDATE challenges SET visible=0 WHERE id=1')
        self.assertEqual(self.client.get('/challenge/1').status_code, 404)
        with app.app_context(), db():
            db().execute(
                'UPDATE contest SET start=?,end=?',
                (int(time.time()) + 10, int(time.time()) + 100),
            )
        self.assertEqual(self.client.get('/challenge/2').status_code, 404)
        self.post('/logout')
        for _ in range(15):
            self.post('/login', username='no-user', password='bad')
        self.assertEqual(self.post('/login', username='no-user', password='bad').status_code, 429)


if __name__ == '__main__':
    unittest.main()
