from flask import Flask, send_file, abort, Blueprint, render_template, request, redirect, session, url_for, jsonify
from datetime import datetime
from flask import flash
from . import db  # SQLAlchemy DB 인스턴스
import os

app = Flask(__name__)

# -- 취약점 1: 디렉토리 트래버설 공격 가능 --
@app.route('/read_file')
def read_file():
    filename = request.args.get('file')  # 사용자 입력 직접 사용 (검증 없음!)
    file_path = os.path.join('static/files', filename)

    try:
        return send_file(file_path)
    except FileNotFoundError:
        abort(404)
main = Blueprint('main', __name__)

# 점검 모드 상태 저장 변수
main.maintenance_mode = False  # False: 정상, True: 점검 중

# 현재 시스템 상태 변수
current_status = {
    "rpm": 0,
    "temperature": 25.0,
    "pressure": 1.0
}

thresholds = {
    "rpm": 3000,
    "temperature": 80,
    "pressure": 5
}

# 하드코딩 사용자 (나중에 DB로 교체 가능)
users = {
    "admin": {"password": "nimdadmin", "role": "admin"},
    "guest": {"password": "guest", "role": "guest"},
    "backup_admin": {"password": "backup_010920", "role": "admin"},  # 숨겨진 계정
}

# DB 모델 예시 (생략 가능)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(20))
    role = db.Column(db.String(10), default='guest')

class RpmLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    timestamp = db.Column(db.String(40))
    value = db.Column(db.String(10))
    current_rpm = db.Column(db.String(10))

class BoardPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    content = db.Column(db.Text)
    timestamp = db.Column(db.String(40))

class MaintenanceSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f"<Maintenance {self.start_time} ~ {self.end_time}>"

# 모든 요청 전에 점검 모드 체크
@main.before_app_request
def check_maintenance_mode():
    # 로그인, 정적 파일, 점검 관련 페이지는 예외 처리
    if request.endpoint in ['main.login', 'main.logout', 'static']:
        return

    # 관리자는 점검 모드 무시
    if 'role' in session and session['role'] == 'admin':
        return

    # 점검 시간 확인
    schedule = MaintenanceSchedule.query.order_by(MaintenanceSchedule.id.desc()).first()
    now = datetime.now()
    if schedule and schedule.start_time <= now <= schedule.end_time:
        return render_template('maintenance.html', start=schedule.start_time, end=schedule.end_time)

@main.route('/maintenance')
def maintenance():
    return render_template('maintenance.html')

@main.route('/maintenance_complete')
def maintenance_complete():
    return render_template('maintenance_complete.html')

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

        users[username] = {"password": password, "role": "guest"}
        return render_template('register.html', success="회원가입이 완료되었습니다.")
    return render_template('register.html')

@main.route('/status')
def status():
    return jsonify({
        "rpm": current_status["rpm"],
        "temperature": current_status["temperature"],
        "pressure": current_status["pressure"],
        "thresholds": thresholds
    })

# -- 취약점 2: 브루트포스 가능한 로그인 --
@main.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)

        # 암호 비교 매우 단순, 로그인 시도 제한 없음
        if user and user["password"] == password:
            session['username'] = username
            session['role'] = user['role']
            return redirect(url_for('main.index'))
        else:
            error = "아이디 또는 비밀번호가 틀렸습니다."

    return render_template('login.html', error=error)

# 원래 코드
#@main.route('/login', methods=['GET', 'POST'])
#def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)

        if user and user["password"] == password:
            session['username'] = username
            session['role'] = user['role']
            return redirect(url_for('main.index'))
        else:
            return render_template('login.html', error="아이디 또는 비밀번호가 잘못되었습니다.")
    return render_template('login.html')

@main.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.login'))

@main.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('main.login'))

    # backup_admin일 경우에만 flag 출력
    flag = None
    if session.get('username') == 'backup_admin':
        flag = "CTF{brute_force_success_and_hidden_admin_found}"

    return render_template(
        'index.html',
        rpm=current_status["rpm"],
        temperature=current_status["temperature"],
        pressure=current_status["pressure"],
        username=session['username'],
        role=session['role'],
        thresholds=thresholds,
        flag=flag
    )

@main.route('/flag')
def flag():
    if session.get('username') == 'backup_admin':
        return "CTF{brute_force_success_and_hidden_admin_found}"
    else:
        return "권한이 없습니다.", 403
    
@main.route('/set_status', methods=['POST'])
def set_status():
    if 'username' not in session:
        return redirect(url_for('main.login'))
    if session.get('role') != 'admin':
        return render_template('index.html', rpm=current_status["rpm"], temperature=current_status["temperature"],
                               pressure=current_status["pressure"], username=session['username'], role=session['role'],
                               thresholds=thresholds, error="⚠️ 관리자 권한이 필요합니다.")

    try:
        new_rpm = int(request.form.get('rpm', current_status["rpm"]))
        new_temp = float(request.form.get('temperature', current_status["temperature"]))
        new_pressure = float(request.form.get('pressure', current_status["pressure"]))

        if new_rpm < 0 or new_rpm > 10000:
            raise ValueError("RPM 값이 유효하지 않습니다.")
        if new_temp < 0 or new_temp > 200:
            raise ValueError("온도 값이 유효하지 않습니다.")
        if new_pressure < 0 or new_pressure > 50:
            raise ValueError("압력 값이 유효하지 않습니다.")

        current_status["rpm"] = new_rpm
        current_status["temperature"] = new_temp
        current_status["pressure"] = new_pressure

        # 로그 기록 생략 가능

        return render_template('index.html', rpm=current_status["rpm"], temperature=current_status["temperature"],
                               pressure=current_status["pressure"], username=session['username'], role=session['role'],
                               thresholds=thresholds, success="✅ 상태가 성공적으로 업데이트되었습니다.")
    except ValueError as e:
        return render_template('index.html', rpm=current_status["rpm"], temperature=current_status["temperature"],
                               pressure=current_status["pressure"], username=session['username'], role=session['role'],
                               thresholds=thresholds, error=f"입력 오류: {str(e)}")

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

# 추가로, 관리자가 점검 모드를 켜고 끌 수 있는 라우트 예시
@main.route('/admin/toggle_maintenance', methods=['POST'])
def toggle_maintenance():
    if 'role' not in session or session['role'] != 'admin':
        return "권한이 없습니다.", 403
    status = request.form.get('status')
    if status == 'on':
        main.maintenance_mode = True
    elif status == 'off':
        main.maintenance_mode = False
    return redirect(url_for('main.config'))

@main.route('/config', methods=['GET', 'POST'])
def config():
    if 'username' not in session or session.get('role') != 'admin':
        return "권한이 없습니다.", 403

    # 점검 시간 정보 불러오기 (최신 하나)
    schedule = MaintenanceSchedule.query.order_by(MaintenanceSchedule.id.desc()).first()

    if request.method == 'POST':
        start_str = request.form.get('start_time')
        end_str = request.form.get('end_time')
        try:
            start_dt = datetime.strptime(start_str, '%Y-%m-%dT%H:%M')
            end_dt = datetime.strptime(end_str, '%Y-%m-%dT%H:%M')
            if start_dt >= end_dt:
                flash("종료 시간은 시작 시간 이후여야 합니다.")
            else:
                # DB에 저장 (새로운 점검 일정 추가)
                new_schedule = MaintenanceSchedule(start_time=start_dt, end_time=end_dt)
                db.session.add(new_schedule)
                db.session.commit()
                flash("점검 시간이 저장되었습니다.")
                schedule = new_schedule
        except Exception as e:
            flash("잘못된 날짜 형식입니다.  예) 2025-07-08T00:00")

    users = User.query.all()
    scada_status = None  # 기존 코드에서 관리하는 상태

    return render_template('config.html', users=users, scada_status=scada_status, maintenance_schedule=schedule)