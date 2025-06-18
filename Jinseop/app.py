from flask import Flask, render_template, request, redirect, url_for, session, flash
import json
import os

app = Flask(__name__)
app.secret_key = 'asdf'

USERS_FILE = 'users.json'
STATUS_FILE = 'status.json'

BOARD_FILE = 'board.json'

def load_users():
    with open('users.json', 'r', encoding='utf-8') as f:
        return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def load_status():
    if os.path.exists(STATUS_FILE):
        with open(STATUS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_board(board_information_list):
    with open(BOARD_FILE, 'w') as f:
        json.dump(board_information_list, f, indent=4)

def load_board():
    with open('board.json', 'r', encoding='utf-8') as f:
        return json.load(f)
    return {}

@app.route('/')
def home():
    return redirect(url_for('homepage'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        if username in users:
            flash('이미 존재하는 사용자입니다.')
        else:
            users[username] = {'password': password}
            save_users(users)
            flash('회원가입 완료. 로그인 해주세요.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            session['user'] = username
            print("로그인 성공:", username)
            return redirect(url_for('homepage'))
        flash('로그인 실패. 다시 시도해주세요.')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    status = load_status()
    return render_template('dashboard.html', user=session['user'], status=status)

@app.route('/homepage')
def homepage():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('homepage.html', user=session['user'])

@app.route('/board')
def board():
    board_included = load_board()
    return render_template('board.html', board_included = board_included)

@app.route('/board_write', methods=['GET', 'POST'])
def board_write():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        users = load_users()
        title = request.form['title']
        context = request.form['context']
        writer = session.get('user')
        post = {
            'title' : title,
            'context' : context,
            'writer' : writer
        }

        board_information_list = [post]

        save_board(board_information_list)
    
    return render_template('board_write.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
