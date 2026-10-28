"""CTF FitWan — ứng dụng thi cá nhân, điểm cố định. Python 3.11+."""
import functools
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
import click
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
# Không dùng khóa cố định trong source. Khóa được giữ qua các lần khởi động.
Path(app.instance_path).mkdir(parents=True, exist_ok=True)
keyfile = Path(app.instance_path) / 'secret.key'
if not keyfile.exists():
    try:
        with keyfile.open('x') as f:
            os.chmod(keyfile, 0o600)
            f.write(secrets.token_hex(32))
    except FileExistsError:
        pass
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY') or keyfile.read_text().strip(),
    DATABASE=os.environ.get('DATABASE', str(Path(app.instance_path) / 'ctf.sqlite3')),
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE') == '1',
    MAX_CONTENT_LENGTH=64 * 1024, PERMANENT_SESSION_LIFETIME=14400,
)


def db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'], timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    conn = g.pop('db', None)
    if conn:
        conn.close()


def setting():
    return db().execute('SELECT * FROM contest WHERE id=1').fetchone()


def flag_digest(flag):
    # Chỉ lưu HMAC, không gửi flag/giá trị băm xuống trình duyệt.
    return hmac.new(app.secret_key.encode(), flag.encode(), hashlib.sha256).hexdigest()


def csrf():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(32)
    return session['csrf']


@app.before_request
def guard():
    g.user = db().execute('SELECT id,username,admin FROM users WHERE id=?',
                          (session.get('uid'),)).fetchone() if session.get('uid') else None
    if request.method == 'POST':
        if not hmac.compare_digest(session.get('csrf', ''), request.form.get('csrf', '')) or not session.get('csrf'):
            abort(400, 'Phiên biểu mẫu không hợp lệ. Tải lại trang rồi thử lại.')


@app.after_request
def headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.context_processor
def context():
    return dict(csrf=csrf, contest=setting(), now=int(time.time()))


@app.template_filter('utc')
def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).strftime('%d/%m/%Y %H:%M:%S UTC') if value else '—'


def login_required(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapped


def admin_required(fn):
    @functools.wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if not g.user['admin']:
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


def rate_limit(key, maximum, seconds):
    # SQLite dùng chung giữa các worker. Mỗi lượt đều được commit ngay.
    conn = db()
    with conn:
        conn.execute('BEGIN IMMEDIATE')
        current = int(time.time())
        conn.execute('DELETE FROM throttle WHERE at < ?', (current - 3600,))
        count = conn.execute('SELECT COUNT(*) FROM throttle WHERE key=? AND at>?',
                             (key, current-seconds)).fetchone()[0]
        if count >= maximum:
            abort(429, 'Quá nhiều yêu cầu. Vui lòng chờ rồi thử lại.')
        conn.execute('INSERT INTO throttle(key,at) VALUES(?,?)', (key, current))


@app.route('/')
def home():
    counts = [db().execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
              for table in ('users', 'challenges', 'solves')]
    news = db().execute('SELECT * FROM announcements ORDER BY id DESC').fetchall()
    return render_template('home.html', counts=counts, news=news)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        rate_limit('register:'+str(request.remote_addr), 10, 3600)
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not re.fullmatch(r'[A-Za-z0-9_]{3,24}', username) or not 10 <= len(password) <= 128:
            flash('Tên 3–24 ký tự chữ/số/gạch dưới; mật khẩu 10–128 ký tự.', 'error')
        else:
            try:
                with db():
                    db().execute('INSERT INTO users(username,password) VALUES(?,?)',
                                 (username, generate_password_hash(password)))
                flash('Đăng ký thành công. Hãy đăng nhập.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Tên tài khoản đã tồn tại.', 'error')
    return render_template('auth.html', register=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        rate_limit('login:'+str(request.remote_addr), 15, 300)
        username = request.form.get('username', '').strip()
        user = db().execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        # Hash giả để tài khoản không tồn tại vẫn thực hiện kiểm tra mật khẩu.
        valid = check_password_hash(user['password'] if user else DUMMY_HASH,
                                    request.form.get('password', ''))
        if user and valid:
            session.clear()
            session['uid'] = user['id']
            session.permanent = True
            return redirect(url_for('challenges'))
        flash('Tên đăng nhập hoặc mật khẩu không đúng.', 'error')
    return render_template('auth.html', register=False)


DUMMY_HASH = generate_password_hash(secrets.token_hex(20))


@app.post('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.get('/challenges')
@login_required
def challenges():
    cfg = setting()
    opened = cfg['start'] <= time.time()
    category = request.args.get('category', '')
    rows = db().execute('SELECT id,title,category,points FROM challenges WHERE visible=1 ORDER BY category,points,id').fetchall() if opened else []
    categories = sorted({r['category'] for r in rows})
    solved = {r[0] for r in db().execute('SELECT challenge_id FROM solves WHERE user_id=?', (g.user['id'],))}
    return render_template('challenges.html', rows=[r for r in rows if not category or r['category']==category],
                           categories=categories, selected=category, solved=solved, opened=opened)


@app.route('/challenge/<int:cid>', methods=['GET', 'POST'])
@login_required
def challenge(cid):
    cfg = setting()
    row = db().execute('SELECT id,title,category,description,points,hint FROM challenges WHERE id=? AND visible=1', (cid,)).fetchone()
    if not row or time.time() < cfg['start']:
        abort(404)
    if request.method == 'POST':
        if g.user['admin']:
            abort(403, 'Tài khoản quản trị không tham gia tính điểm.')
        rate_limit('submit:'+str(g.user['id']), 10, 60)
        conn = db()
        with conn:
            # Khóa trước khi kiểm tra, ghi lượt nộp và solve trong một transaction.
            conn.execute('BEGIN IMMEDIATE')
            cfg = setting()
            current = int(time.time())
            if not cfg['start'] <= current < cfg['end']:
                abort(403, 'Cuộc thi chưa mở hoặc đã kết thúc.')
            exists = conn.execute('SELECT 1 FROM solves WHERE user_id=? AND challenge_id=?', (g.user['id'], cid)).fetchone()
            if exists:
                flash('Bạn đã giải thử thách này.', 'info')
            else:
                supplied = request.form.get('flag', '')
                expected = conn.execute('SELECT flag_hash FROM challenges WHERE id=?', (cid,)).fetchone()[0]
                correct = hmac.compare_digest(flag_digest(supplied), expected)
                conn.execute('INSERT INTO submissions(user_id,challenge_id,correct,at) VALUES(?,?,?,?)',
                             (g.user['id'], cid, int(correct), current))
                if correct:
                    conn.execute('INSERT INTO solves(user_id,challenge_id,points,at) VALUES(?,?,?,?)',
                                 (g.user['id'], cid, row['points'], current))
                flash('Chính xác! Điểm đã được cộng.' if correct else 'Flag chưa chính xác.', 'success' if correct else 'error')
        return redirect(url_for('challenge', cid=cid))
    solved = db().execute('SELECT 1 FROM solves WHERE user_id=? AND challenge_id=?', (g.user['id'], cid)).fetchone()
    return render_template('challenge.html', row=row, solved=solved)


@app.get('/scoreboard')
def scoreboard():
    rows = db().execute('''SELECT u.username,COALESCE(SUM(s.points),0) score,
        COUNT(s.challenge_id) solved,MAX(s.at) last_solve,MAX(s.id) last_id
        FROM users u LEFT JOIN solves s ON s.user_id=u.id WHERE u.admin=0
        GROUP BY u.id ORDER BY score DESC,COALESCE(last_solve,0),COALESCE(last_id,0),u.id''').fetchall()
    return render_template('scoreboard.html', rows=rows)


@app.get('/profile')
@login_required
def profile():
    rows = db().execute('''SELECT c.title,s.correct,s.at FROM submissions s JOIN challenges c
        ON c.id=s.challenge_id WHERE s.user_id=? ORDER BY s.id DESC LIMIT 100''', (g.user['id'],)).fetchall()
    return render_template('profile.html', rows=rows)


def integer(name, low, high):
    try:
        value = int(request.form.get(name, ''))
    except ValueError:
        abort(400, 'Trường số không hợp lệ: '+name)
    if not low <= value <= high:
        abort(400, 'Giá trị ngoài giới hạn: '+name)
    return value


def text(name, maximum, required=True):
    value = request.form.get(name, '').strip()
    if (required and not value) or len(value) > maximum:
        abort(400, 'Trường không hợp lệ: '+name)
    return value


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    if request.method == 'POST':
        action = request.form.get('action')
        with db():
            if action == 'challenge':
                cid = integer('cid', 0, 2147483647)
                title, category = text('title', 100), text('category', 40)
                description, hint = text('description', 10000), text('hint', 1000, False)
                points, visible = integer('points', 1, 10000), int('visible' in request.form)
                flag = request.form.get('flag', '')
                if len(flag) > 256 or (not cid and not flag):
                    abort(400, 'Flag mới cần 1–256 ký tự.')
                if cid:
                    old = db().execute('SELECT * FROM challenges WHERE id=?', (cid,)).fetchone()
                    if not old:
                        abort(404)
                    if old['points'] != points and db().execute('SELECT 1 FROM solves WHERE challenge_id=?', (cid,)).fetchone():
                        abort(400, 'Không đổi điểm khi bài đã có người giải.')
                    db().execute('UPDATE challenges SET title=?,category=?,description=?,hint=?,points=?,visible=?,flag_hash=? WHERE id=?',
                                 (title,category,description,hint,points,visible,flag_digest(flag) if flag else old['flag_hash'],cid))
                else:
                    db().execute('INSERT INTO challenges(title,category,description,hint,points,visible,flag_hash) VALUES(?,?,?,?,?,?,?)',
                                 (title,category,description,hint,points,visible,flag_digest(flag)))
            elif action == 'contest':
                start, end = integer('start', 0, 4102444800), integer('end', 1, 4102444800)
                if end <= start:
                    abort(400, 'Thời điểm kết thúc phải sau bắt đầu.')
                db().execute('UPDATE contest SET title=?,start=?,end=? WHERE id=1', (text('title',100), start,end))
            elif action == 'news':
                db().execute('INSERT INTO announcements(body,at) VALUES(?,?)', (text('body',3000),int(time.time())))
            else:
                abort(400)
        flash('Đã lưu thay đổi.', 'success')
        return redirect(url_for('admin'))
    edit = db().execute('SELECT id,title,category,description,hint,points,visible FROM challenges WHERE id=?', (request.args.get('edit', type=int),)).fetchone()
    rows = db().execute('SELECT id,title,category,points,visible FROM challenges ORDER BY id DESC').fetchall()
    return render_template('admin.html', rows=rows, edit=edit)


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
@app.errorhandler(429)
def error(err):
    return render_template('error.html', error=err), err.code


@app.cli.command('init-db')
def init_db():
    """Tạo bảng nếu chưa có; không xóa dữ liệu hiện tại."""
    db().executescript((Path(app.root_path)/'schema.sql').read_text())
    with db():
        db().execute('INSERT OR IGNORE INTO contest(id,title,start,end) VALUES(1,?,?,?)',
                     ('CTF FitWan',int(time.time())-60,int(time.time())+7*86400))
    click.echo('Đã khởi tạo cơ sở dữ liệu.')


@app.cli.command('create-admin')
@click.argument('username')
@click.password_option(confirmation_prompt=True)
def create_admin(username, password):
    """Tạo admin riêng, không có tài khoản/mật khẩu mặc định."""
    if not re.fullmatch(r'[A-Za-z0-9_]{3,24}',username) or not 10 <= len(password) <=128:
        raise click.ClickException('Tên 3–24 ký tự chữ/số/_; mật khẩu 10–128 ký tự.')
    try:
        with db():
            db().execute('INSERT INTO users(username,password,admin) VALUES(?,?,1)',
                         (username,generate_password_hash(password)))
    except sqlite3.IntegrityError:
        raise click.ClickException('Tên đã tồn tại; không tự động nâng quyền tài khoản.')
    click.echo('Đã tạo quản trị viên.')


@app.cli.command('seed-demo')
def seed_demo():
    """Chỉ dùng học tập: flag mẫu công khai trong source."""
    examples = [
        ('Base64 đầu tiên','Cryptography',100,'Giải mã chuỗi: Q1RGe2I0czY0X2lzX2Vhc3l9','Base64 không phải mã hóa bảo mật.','CTF{b4s64_is_easy}'),
        ('Đọc mã nguồn','Web',100,'Tìm flag trong đoạn HTML mẫu: <!-- CTF{view_source} -->','Xem nội dung chú thích HTML.','CTF{view_source}'),
        ('Mã Hex','Forensics',150,'Đổi các byte hex thành văn bản: 43 54 46 7b 68 65 78 5f 66 75 6e 7d','Mỗi cặp hex biểu diễn một byte.','CTF{hex_fun}'),
    ]
    with db():
        for title,category,points,description,hint,flag in examples:
            if not db().execute('SELECT 1 FROM challenges WHERE title=?',(title,)).fetchone():
                db().execute('INSERT INTO challenges(title,category,points,description,hint,flag_hash,visible) VALUES(?,?,?,?,?,?,1)',
                             (title,category,points,description,hint,flag_digest(flag)))
    click.echo('Đã thêm 3 bài demo; thay bài và flag trước thi thật.')