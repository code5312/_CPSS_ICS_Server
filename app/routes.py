from flask import Blueprint, render_template, request, redirect, session, url_for, jsonify
from datetime import datetime, timedelta
import random

login_attempts = {}

main = Blueprint('main', __name__)

current_rpm = 0

thresholds = {
    "rpm": 3000,
    "temperature": 80,
    "pressure": 5
}
# 사용자 계정 정보(하드 코딩 해놓고 추후에 확인)
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "guest": {"password": "guest123", "role": "guest"},
}

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
    return jsonify({
        "rpm": current_rpm,
        "temperature": random.randint(20, 100),
        "pressure": round(random.uniform(1.0, 10.0), 2),
        "thresholds": thresholds
    })

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)

        now = datetime.now()
        user_record = login_attempts.get(username, {"count": 0, "locked_until": None})

        # 🔒 잠금 시간 확인
        if user_record["locked_until"] and now < user_record["locked_until"]:
            wait_time = int((user_record["locked_until"] - now).total_seconds() // 60) + 1
            return render_template('login.html', error=f"❌ Your account has been locked. Please try again in {wait_time}minutes.")

        # 🔓 로그인 성공
        if user and user["password"] == password:
            session['username'] = username
            session['role'] = user['role']
            login_attempts[username] = {"count": 0, "locked_until": None}
            return redirect(url_for('main.index'))

        # ❌ 로그인 실패
        user_record["count"] += 1
        if user_record["count"] >= 5:
            user_record["locked_until"] = now + timedelta(minutes=5)
            error = "❌ Your account has been locked for 5 minutes due to 5 failed login attempts."
        else:
            remaining = 5 - user_record["count"]
            error = f"Login failed. Number of attempts remaining: {remaining}"

        login_attempts[username] = user_record
        return render_template('login.html', error=error)

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
        rpm=current_rpm,
        username=session['username'],
        role=session['role'],
        thresholds=thresholds
    )


@main.route('/set_status', methods=['POST'])
def set_status():
    global current_rpm
    if 'username' not in session:
        return redirect(url_for('main.login'))

    if session.get('role') != 'admin':
        return render_template('index.html', rpm=current_rpm, username=session['username'], role=session['role'],
                               thresholds=thresholds, error="⚠️ 관리자 권한이 필요합니다.")

    try:
        new_rpm = int(request.form.get('rpm', current_rpm))
        new_temp = float(request.form.get('temperature', thresholds['temperature']))
        new_pressure = float(request.form.get('pressure', thresholds['pressure']))

        # 유효성 검사
        if new_rpm < 0 or new_rpm > 10000:
            raise ValueError("RPM 값이 유효하지 않습니다.")
        if new_temp < 0 or new_temp > 200:
            raise ValueError("온도 값이 유효하지 않습니다.")
        if new_pressure < 0 or new_pressure > 50:
            raise ValueError("압력 값이 유효하지 않습니다.")

        # 값 저장
        current_rpm = new_rpm
        thresholds['temperature'] = new_temp
        thresholds['pressure'] = new_pressure

        message = "✅ 상태가 성공적으로 업데이트되었습니다."
        return render_template('index.html', rpm=current_rpm, username=session['username'], role=session['role'],
                               thresholds=thresholds, success=message)

    except ValueError as e:
        return render_template('index.html', rpm=current_rpm, username=session['username'], role=session['role'],
                               thresholds=thresholds, error=f"입력 오류: {str(e)}")