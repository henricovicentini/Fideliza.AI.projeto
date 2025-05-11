###### Importações principais do Flask e extensões ######

from flask import Flask, render_template, request, redirect, url_for, flash  # Flask básico, templates, redirecionamentos e mensagens de erro
from flask_sqlalchemy import SQLAlchemy  # ORM para manipulação do banco de dados
from flask_migrate import Migrate  # Gerencia migrações do banco (estrutura e versões)
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user  # Gerencia sessões de login e autenticação
from werkzeug.security import generate_password_hash, check_password_hash  # Criptografa senhas com hash seguro
from flask_wtf import FlaskForm  # Integração de formulários HTML com Flask de forma segura
from wtforms import StringField, PasswordField, BooleanField, SubmitField  # Campos que serão usados nos formulários
from wtforms.validators import DataRequired, Email, EqualTo, Length  # Validações dos campos dos formulários
import email_validator  # Adicionada para suportar validação de e-mail
import secrets, time, os

###### Configurações da aplicação ######

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Garantir que a pasta instance exista e o banco de dados também
os.makedirs(app.instance_path, exist_ok=True)
if not os.path.exists(os.path.join(app.instance_path, 'users.db')):
    open(os.path.join(app.instance_path, 'users.db'), 'w').close()

###### Inicialização do banco e gerenciamento de migrações ######

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

LOCKOUT_TIME = 300

###### Modelo de usuário - tabela no banco ######

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.Integer, default=None)
    last_login = db.Column(db.Integer, default=None)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

###### Formulário de login ######

class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    remember_me = BooleanField('Lembrar-me')
    submit = SubmitField('Entrar')

###### Formulário de registro ######

class RegistrationForm(FlaskForm):
    name = StringField('Nome', validators=[DataRequired(), Length(min=2, max=120)])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrar')

###### Rota principal (home) - renderiza a página inicial ######

@app.route('/')
def home():
    return render_template('index.html')

###### Rota de login ######

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if not user:
            flash('Credenciais inválidas', 'danger')
            return render_template('login.html', form=form)

        current_time = int(time.time())

        if user.locked_until and user.locked_until > current_time:
            flash(f'Conta bloqueada. Tente novamente em {user.locked_until - current_time} segundos.', 'danger')
            return render_template('login.html', form=form)

        if not check_password_hash(user.password, form.password.data):
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked_until = current_time + LOCKOUT_TIME
            db.session.commit()
            flash('Credenciais inválidas', 'danger')
            return render_template('login.html', form=form)

        user.failed_attempts = 0
        user.locked_until = None
        user.last_login = current_time
        db.session.commit()

        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)

###### Rota de registro de usuário ######

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('E-mail já registrado.', 'danger')
            return render_template('register.html', form=form)

        hashed_pw = generate_password_hash(form.password.data)
        user = User(name=form.name.data, email=form.email.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Registrado com sucesso!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

###### Rota protegida - painel do usuário logado ######

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

###### Rota de logout ######

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
