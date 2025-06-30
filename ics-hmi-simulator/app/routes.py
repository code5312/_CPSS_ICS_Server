from flask import Blueprint, render_template, request, redirect, session, url_for, jsonify, flash
from flask.sessions import SecureCookieSessionInterface
from datetime import datetime, timedelta
from . import db  # db 인스턴스 import
import os

login_attempts = {}

main = Blueprint('main', __name__)

current_status = {
    "rpm": 0,
    "temperature": 25.0,  # 초기 온도
    "pressure": 1.0       # 초기 압력
}

thresholds = {
    "rpm": 3000,
    "temperature": 80,
    "pressure": 5
}
# 사용자 계정 정보(하드 코딩 해놓고 추후에 확인)
users = {
    "admin": {"password": "nimdadmin", "role": "admin"},
    "guest": {"password": "guest", "role": "guest"},
}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(20))
    # role 필드는 기존 users dict와 호환 위해 추가 가능
    role = db.Column(db.String(10), default='guest')

class RpmLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    timestamp = db.Column(db.String(40))
    value = db.Column(db.String(10))  # 입력된 값
    current_rpm = db.Column(db.String(10))  # 최종 rpm

class BoardPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    content = db.Column(db.Text)
    timestamp = db.Column(db.String(40))

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if username in users:
            return render_template('register.html', error="이미 존재하는 아이디입니다.")
        if password != confirm_password:
            return render_template('register.html', error="비밀번호가 일치하지 않습니다.")

        users[username] = {"password": password, "role": "guest"}  # 기본적으로 guest로 추가
        return render_template('register.html', success="회원가입이 완료되었습니다.")

    return render_template('register.html')

@main.route('/status')
def status():
    sid = request.cookies.get('session')
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 디코딩된 세션 ID만 따로 로그 파일에 기록
    si = SecureCookieSessionInterface()
    data = si.get_signing_serializer(current_app).loads(sid)

    with open('session_log.txt', 'a') as f:
        f.write(f"{now} - Decoded session: {data}\n")
        
    return jsonify({
        "rpm": current_status["rpm"],
        "temperature": current_status["temperature"],
        "pressure": current_status["pressure"],
        "thresholds": thresholds
    })

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)

        # 🔓 로그인 성공
        if user and user["password"] == password:
            session['username'] = username
            session['role'] = user['role']
            login_attempts[username] = {"count": 0, "locked_until": None}
            return redirect(url_for('main.index'))

    return render_template('login.html')

@main.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.login'))

@main.route('/admin/reset_user', methods=['POST'])
def reset_user():
    if 'username' not in session or session.get('role') != 'admin':
        return "Error, You don't have permission.", 403

    username = request.form.get('target_user')
    if username in login_attempts:
        login_attempts[username] = {"count": 0, "locked_until": None}
        return f"{username}'s Login attempts have been reset."
    else:
        return f"{username} << No login history'."

@main.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('main.login'))

    return render_template(
        'index.html',
        rpm=current_status["rpm"],
        temperature=current_status["temperature"],
        pressure=current_status["pressure"],
        username=session['username'],
        role=session['role'],
        thresholds=thresholds
    )

@main.route('/set_status', methods=['POST'])
def set_status():
    global current_status
    if 'username' not in session:
        return redirect(url_for('main.login'))

    if session.get('role') != 'admin':
        return render_template('index.html', rpm=current_status["rpm"], temperature=current_status["temperature"], pressure=current_status["pressure"], username=session['username'], role=session['role'],
                               thresholds=thresholds, error="⚠️ 관리자 권한이 필요합니다.")

    try:
        new_rpm = int(request.form.get('rpm', current_status["rpm"]))
        new_temp = float(request.form.get('temperature', current_status["temperature"]))
        new_pressure = float(request.form.get('pressure', current_status["pressure"]))

        # 유효성 검사
        if new_rpm < 0 or new_rpm > 10000:
            raise ValueError("RPM 값이 유효하지 않습니다.")
        if new_temp < 0 or new_temp > 200:
            raise ValueError("온도 값이 유효하지 않습니다.")
        if new_pressure < 0 or new_pressure > 50:
            raise ValueError("압력 값이 유효하지 않습니다.")

        # 값 저장
        current_status["rpm"] = new_rpm
        current_status["temperature"] = new_temp
        current_status["pressure"] = new_pressure

        # 로그 기록 (rpm 변경 시)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log = RpmLog(username=session['username'], timestamp=now, value=str(new_rpm), current_rpm=str(current_status["rpm"]))
        db.session.add(log)
        db.session.commit()

        message = "✅ 상태가 성공적으로 업데이트되었습니다."
        return render_template('index.html', rpm=current_status["rpm"], temperature=current_status["temperature"], pressure=current_status["pressure"], username=session['username'], role=session['role'],
                               thresholds=thresholds, success=message)

    except ValueError as e:
        return render_template('index.html', rpm=current_status["rpm"], temperature=current_status["temperature"], pressure=current_status["pressure"], username=session['username'], role=session['role'],
                               thresholds=thresholds, error=f"입력 오류: {str(e)}")

@main.route('/set_rpm', methods=['POST'])
def set_rpm():
    if 'username' not in session:
        return redirect(url_for('main.login'))
    if session.get('role') != 'admin':
        return render_template('index.html', rpm=current_status["rpm"], temperature=current_status["temperature"], pressure=current_status["pressure"], username=session['username'], role=session['role'],
                               thresholds=thresholds, error="⚠️ 관리자 권한이 필요합니다.")
    try:
        new_rpm = int(request.form.get('rpm', current_status["rpm"]))
        if new_rpm < 0 or new_rpm > 10000:
            raise ValueError("RPM 값이 유효하지 않습니다.")
        current_status["rpm"] = new_rpm
        # 로그 기록
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log = RpmLog(username=session['username'], timestamp=now, value=str(new_rpm), current_rpm=str(current_status["rpm"]))
        db.session.add(log)
        db.session.commit()
        message = "✅ 회전수가 성공적으로 변경되었습니다."
        return render_template('index.html', rpm=current_status["rpm"], temperature=current_status["temperature"], pressure=current_status["pressure"], username=session['username'], role=session['role'],
                               thresholds=thresholds, success=message)
    except ValueError as e:
        return render_template('index.html', rpm=current_status["rpm"], temperature=current_status["temperature"], pressure=current_status["pressure"], username=session['username'], role=session['role'],
                               thresholds=thresholds, error=f"입력 오류: {str(e)}")

@main.route('/api/rpm_logs')
def api_rpm_logs():
    logs = db.session.query(RpmLog).order_by(RpmLog.id.desc()).limit(10).all()
    return jsonify([
        {
            'timestamp': log.timestamp,
            'username': log.username,
            'value': log.value,
            'current_rpm': log.current_rpm
        } for log in logs
    ])

@main.route('/board', methods=['GET', 'POST'])
def board():
    if 'username' not in session:
        return redirect(url_for('main.login'))
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        if content:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            post = BoardPost(username=session['username'], content=content, timestamp=now)
            db.session.add(post)
            db.session.commit()
    posts = BoardPost.query.order_by(BoardPost.id.desc()).limit(20).all()
    return render_template('board.html', posts=posts, username=session['username'])

@main.route('/board/delete/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('main.login'))
    post = BoardPost.query.get_or_404(post_id)
    is_admin = session.get('role') == 'admin'
    if is_admin or post.username == session['username']:
        db.session.delete(post)
        db.session.commit()
    return redirect(url_for('main.board'))
