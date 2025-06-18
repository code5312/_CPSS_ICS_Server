from flask import Flask, render_template, request, redirect, url_for, session
import json, os, uuid

app = Flask(__name__)
app.secret_key = 'your-secret-key'

STATUS_FILE = 'status.json'
USER_FILE = 'users.json'
POSTS_FILE = 'posts.json'

# JSON 파일 초기화
if not os.path.exists(STATUS_FILE):
    with open(STATUS_FILE, 'w') as f:
        json.dump({"PLC_1": {"machine_status": "STOPPED", "rpm": 0}}, f)

if not os.path.exists(USER_FILE):
    with open(USER_FILE, 'w') as f:
        json.dump({"admin": {"password": "admin123", "role": "admin"}}, f)

# 유틸 함수

def load_json(file):
    with open(file) as f:
        return json.load(f)

def save_json(file, data):
    with open(file, 'w') as f:
        json.dump(data, f)

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_json(USER_FILE)

        if username in users and users[username]['password'] == password:
            session['username'] = username
            session['role'] = users[username]['role']
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="로그인 실패")
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# PLC 리스트 대시보드
@app.route('/')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    status = load_json(STATUS_FILE)
    return render_template('dashboard.html', plc_list=status.keys(), status=status)

# PLC 추가 폼 페이지 (admin 전용)
@app.route('/add_plc_form')
def add_plc_form():
    if session.get('role') != 'admin':
        return "권한 없음", 403
    return render_template('add_plc.html')

# PLC 추가 (admin 전용)
@app.route('/add_plc', methods=['POST'])
def add_plc():
    if session.get('role') != 'admin':
        return "권한 없음", 403

    plc_id = request.form.get('plc_id')
    machine_status = request.form.get('machine_status')
    rpm = int(request.form.get('rpm'))

    status = load_json(STATUS_FILE)
    if plc_id and plc_id not in status:
        status[plc_id] = {"machine_status": machine_status, "rpm": rpm}
        save_json(STATUS_FILE, status)
    return redirect(url_for('dashboard'))

# 특정 PLC 제어
@app.route('/plc/<plc_id>')
def plc_page(plc_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    status = load_json(STATUS_FILE).get(plc_id, {"machine_status": "UNKNOWN", "rpm": 0})
    return render_template('plc_control.html', plc_id=plc_id, status=status, is_admin=session.get('role') == 'admin')

# 회전기 ON/OFF 제어
@app.route('/plc/<plc_id>/control', methods=['POST'])
def plc_control(plc_id):
    if session.get('role') != 'admin':
        return "권한 없음", 403
    status = load_json(STATUS_FILE)
    if plc_id not in status:
        status[plc_id] = {}
    action = request.form.get('action')
    status[plc_id]['machine_status'] = 'RUNNING' if action == 'start' else 'STOPPED'
    save_json(STATUS_FILE, status)
    return redirect(url_for('plc_page', plc_id=plc_id))

# 회전수 설정
@app.route('/plc/<plc_id>/rpm', methods=['POST'])
def plc_rpm(plc_id):
    if session.get('role') != 'admin':
        return "권한 없음", 403
    rpm = int(request.form.get('rpm'))
    status = load_json(STATUS_FILE)
    if plc_id not in status:
        status[plc_id] = {}
    status[plc_id]['rpm'] = rpm
    save_json(STATUS_FILE, status)
    return redirect(url_for('plc_page', plc_id=plc_id))

# 게시판 목록
@app.route('/board')
def board():
    posts = load_json(POSTS_FILE)
    return render_template('board.html', posts=posts, username=session.get('username'), role=session.get('role'))

# 게시글 작성 폼
@app.route('/board/new')
def new_post():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('new_post.html')

# 게시글 작성 처리
@app.route('/board/create', methods=['POST'])
def create_post():
    posts = load_json(POSTS_FILE)
    post_id = str(uuid.uuid4())
    posts[post_id] = {
        'title': request.form['title'],
        'content': request.form['content'],
        'author': session.get('username')
    }
    save_json(POSTS_FILE, posts)
    return redirect(url_for('board'))

# 게시글 보기
@app.route('/board/<post_id>')
def view_post(post_id):
    posts = load_json(POSTS_FILE)
    post = posts.get(post_id)
    return render_template('view_post.html', post=post, post_id=post_id, username=session.get('username'), role=session.get('role'))

# 게시글 삭제
@app.route('/board/<post_id>/delete')
def delete_post(post_id):
    posts = load_json(POSTS_FILE)
    post = posts.get(post_id)
    if post and (session.get('username') == post['author'] or session.get('role') == 'admin'):
        posts.pop(post_id)
        save_json(POSTS_FILE, posts)
    return redirect(url_for('board'))

# 게시글 수정 폼
@app.route('/board/<post_id>/edit')
def edit_post(post_id):
    posts = load_json(POSTS_FILE)
    post = posts.get(post_id)
    if post and (session.get('username') == post['author'] or session.get('role') == 'admin'):
        return render_template('edit_post.html', post=post, post_id=post_id)
    return redirect(url_for('board'))

# 게시글 수정 처리
@app.route('/board/<post_id>/update', methods=['POST'])
def update_post(post_id):
    posts = load_json(POSTS_FILE)
    post = posts.get(post_id)
    if post and (session.get('username') == post['author'] or session.get('role') == 'admin'):
        post['title'] = request.form['title']
        post['content'] = request.form['content']
        save_json(POSTS_FILE, posts)
    return redirect(url_for('view_post', post_id=post_id))

if __name__ == '__main__':
    app.run(debug=True)
