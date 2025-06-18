from flask import *
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecret"  # 취약한 고정 키
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(20))

with app.app_context():
    db.create_all()


class RpmLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    timestamp = db.Column(db.String(40))
    value = db.Column(db.String(10))  # 입력된 값
    current_rpm = db.Column(db.String(10))  # 최종 rpm
    
with app.app_context():
    db.create_all()





@app.route('/')
def index():
    # 기본 루트에서 대시보드로 이동
    return redirect('/dashboard')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form['password'] == request.form['re-password']:
            user = User(username=request.form['username'], password=request.form['password'])
            db.session.add(user)
            db.session.commit()
            return redirect('/login')
        else:
            flash("Passwords do not match")  # alert 출력
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':    
        user = User.query.filter_by(username=request.form['username'], password=request.form['password']).first()
        if user:
            session['user'] = user.username
            return redirect('/dashboard')
        flash("Login Failed")  # alert 출력
    return render_template('login.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    user = session.get('user', None)
    rpm = None

    if user and request.method == 'POST':
        if user == 'admin':
            rpm = request.form.get('rpm')

            # 로그 기록
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log = RpmLog(username=user, timestamp=now, value=rpm, current_rpm=rpm)
            db.session.add(log)
            db.session.commit()
        else:
            flash("Invalid credential")

    latest_rpm = db.session.query(RpmLog).order_by(RpmLog.id.desc()).first()
    logs = db.session.query(RpmLog).order_by(RpmLog.id.desc()).limit(10).all() #최근 10개만

    return render_template('dashboard.html', user=user, rpm=rpm, latest_rpm=latest_rpm, logs=logs)

@app.route('/api/rpm_logs')
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

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/config', methods=['GET', 'POST'])
def admin_config():
    if 'user' not in session or session['user'] != 'admin':
        flash("Unauthorized access")
        return redirect('/dashboard')

    users = User.query.all()


    scada_status = ""
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'reset':
            scada_status = "🧹 PLC 시스템 초기화 완료"
        elif action == 'shutdown':
            scada_status = "⚠️ SCADA 시스템 긴급 정지 수행됨"
        elif action.startswith("delete_user_"):
            user_id = int(action.replace("delete_user_", ""))
            user_to_delete = User.query.get(user_id)
            if user_to_delete and user_to_delete.username != 'admin':
                db.session.delete(user_to_delete)
                db.session.commit()
                flash(f"Deleted user {user_to_delete.username}")
                return redirect('/config')

    return render_template('config.html', users=users, scada_status=scada_status)


if __name__ == '__main__':
    app.run(debug=True)
