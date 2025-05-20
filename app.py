###### Importações principais do Flask e extensões ######

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
import secrets, time, os
import pandas as pd
import matplotlib.pyplot as plt
import datetime


###### Configurações da aplicação ######

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Limite 5MB para upload

os.makedirs(app.instance_path, exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

if not os.path.exists(os.path.join(app.instance_path, 'users.db')):
    open(os.path.join(app.instance_path, 'users.db'), 'w').close()

# Criar diretórios se ainda não existirem
os.makedirs('static/uploads', exist_ok=True)
os.makedirs('static/plots', exist_ok=True)


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
    email = StringField('E-mail', render_kw={"readonly": True})  # Campo email readonly
    current_password = PasswordField('Senha Atual', validators=[DataRequired()])
    new_password = PasswordField('Nova Senha', validators=[Length(min=6)])
    confirm_new_password = PasswordField('Confirmar Nova Senha', validators=[EqualTo('new_password', message='As senhas não coincidem.')])
    submit = SubmitField('Salvar Alterações')


###### Rota principal - redireciona para dashboard se logado ######

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


###### Rota de login ######

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

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
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

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


###### Rota protegida - dashboard com upload de CSV e gráfico ######

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    graph_url = None

    if request.method == 'POST':
        # Verifica se arquivo foi enviado no formulário
        if 'csvfile' not in request.files:
            flash('Nenhum arquivo selecionado.', 'danger')
            return redirect(url_for('dashboard'))
        file = request.files['csvfile']
        if file.filename == '':
            flash('Nenhum arquivo selecionado.', 'danger')
            return redirect(url_for('dashboard'))

        # Salva arquivo com nome seguro na pasta uploads
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            # Carrega CSV com pandas (ajuste aqui se seu CSV for diferente)
            df = pd.read_csv(filepath)

            # Exemplo simples: plota gráfico de linha do primeiro e segundo colunas
            if df.shape[1] < 2:
                flash('CSV precisa ter pelo menos 2 colunas para plotar gráfico.', 'danger')
                return redirect(url_for('dashboard'))

            plt.figure(figsize=(8,4))
            plt.plot(df.iloc[:,0], df.iloc[:,1], marker='o')
            plt.title('Gráfico do CSV enviado')
            plt.xlabel(df.columns[0])
            plt.ylabel(df.columns[1])
            plt.grid(True)

            # Salva imagem do gráfico na pasta static
            img_filename = f'plot_{int(time.time())}.png'
            img_path = os.path.join('static', img_filename)
            plt.savefig(img_path)
            plt.close()

            graph_url = url_for('static', filename=img_filename)

        except Exception as e:
            flash(f'Erro ao processar CSV: {e}', 'danger')

    return render_template('dashboard.html', user=current_user, graph_url=graph_url)


###### Rota de logout ######

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


###### Rota de perfil - permite apenas visualizar o email e alterar a senha ######

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

        if form.new_password.data:
            current_user.password = generate_password_hash(form.new_password.data)
            db.session.commit()
            flash('Senha atualizada com sucesso.', 'success')
        else:
            flash('Nenhuma alteração realizada.', 'info')

        return redirect(url_for('perfil'))

    return render_template('perfil.html', form=form)


@app.template_filter('datetimeformat')
def datetimeformat(value):
    # Converte timestamp UNIX para string data formatada
    return datetime.datetime.fromtimestamp(value).strftime('%d/%m/%Y %H:%M:%S')


ALLOWED_EXTENSIONS = {'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/view', methods=['GET', 'POST'])
@login_required
def view():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Nenhum arquivo enviado.', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('Nenhum arquivo selecionado.', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join('static/uploads', filename)
            file.save(filepath)

            try:
                df = pd.read_csv(filepath)

                # Gráfico 1: Distribuição de churn
                plt.figure(figsize=(6,4))
                df['Exited'].value_counts().plot(kind='bar', color=['green', 'red'])
                plt.title('Distribuição de Clientes - Churn')
                plt.xlabel('Churn (0=Não, 1=Sim)')
                plt.ylabel('Número de Clientes')
                plot1_path = 'static/plots/churn_dist.png'
                plt.tight_layout()
                plt.savefig(plot1_path)
                plt.close()

                # Gráfico 2: Idade média por churn
                plt.figure(figsize=(6,4))
                df.groupby('Exited')['Age'].mean().plot(kind='bar', color=['blue', 'orange'])
                plt.title('Idade Média por Churn')
                plt.xlabel('Churn (0=Não, 1=Sim)')
                plt.ylabel('Idade Média')
                plot2_path = 'static/plots/idade_churn.png'
                plt.tight_layout()
                plt.savefig(plot2_path)
                plt.close()

                # Gráfico 3: Correlação com churn (selecionando apenas colunas numéricas)
                correlations = df.corr(numeric_only=True)['Exited'].sort_values(ascending=False)
                correlations = correlations.drop('Exited')

                plt.figure(figsize=(8,6))
                correlations.plot(kind='barh', color='purple')
                plt.title('Correlação de Atributos com o Churn')
                plt.xlabel('Correlação')
                plot3_path = 'static/plots/correlacoes.png'
                plt.tight_layout()
                plt.savefig(plot3_path)
                plt.close()

                return render_template('view.html', plots=[plot1_path, plot2_path, plot3_path])

            except Exception as e:
                flash(f'Erro ao processar o arquivo: {e}', 'danger')
                return redirect(request.url)

        else:
            flash('Formato de arquivo inválido. Envie um CSV.', 'danger')
            return redirect(request.url)

    return render_template('view.html', plots=[])


###### Inicializa a aplicação ######

if __name__ == '__main__':
    app.run(debug=True)
