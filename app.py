###### Importações principais do Flask e extensões ######

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
import secrets, time, os

###### Configurações da aplicação ######

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    locked_until = db.Column(db.Integer, default=None, nullable=True)
    last_login = db.Column(db.Integer, default=None)

###### Carregamento do usuário logado ######

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

###### Formulário de perfil do usuário ######

class ProfileForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    current_password = PasswordField('Senha Atual', validators=[DataRequired()])
    new_password = PasswordField('Nova Senha', validators=[Length(min=6)])
    confirm_new_password = PasswordField('Confirmar Nova Senha', validators=[EqualTo('new_password', message='As senhas não coincidem.')])
    submit = SubmitField('Salvar Alterações')

###### Rota principal - página inicial ######

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

###### Rota de registro ######

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

###### Rota protegida - dashboard ######

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

###### Rota de perfil - permite editar email e senha ######

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    form = ProfileForm()

    if request.method == 'GET':
        form.email.data = current_user.email

    if form.validate_on_submit():
        if not check_password_hash(current_user.password, form.current_password.data):
            flash('Senha atual incorreta.', 'danger')
            return render_template('perfil.html', form=form)

        if form.email.data != current_user.email:
            if User.query.filter_by(email=form.email.data).first():
                flash('Este e-mail já está em uso.', 'danger')
                return render_template('perfil.html', form=form)
            current_user.email = form.email.data

        if form.new_password.data:
            current_user.password = generate_password_hash(form.new_password.data)

        db.session.commit()
        flash('Perfil atualizado com sucesso.', 'success')
        return redirect(url_for('perfil'))

    return render_template('perfil.html', form=form)

###### Inicializa a aplicação ######

if __name__ == '__main__':
    app.run(debug=True)
