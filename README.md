
# 📊 Fideliza AI — Sistema Inteligente de Fidelização de Usuários

**Fideliza AI** é uma aplicação web desenvolvida com Python e Flask, focada em proporcionar um ambiente seguro e personalizado para gerenciamento de usuários e análise de dados. Ideal para projetos que requerem autenticação robusta, dashboards informativos e integração com dados analíticos.

---

## 🚀 Funcionalidades Principais

- ✅ Cadastro de usuários com **registro e login seguros**  
- 🔐 Autenticação com **gerenciamento de sessões e segurança reforçada**  
- 🛡️ **Bloqueio automático de conta** após 5 tentativas de login incorretas  
- 📈 Dashboard personalizado após login, com foco na experiência do usuário  

---

## 🛠️ Tecnologias Utilizadas

- **Linguagem:** Python 3.x  
- **Framework:** Flask (3.1.1)  
- **Banco de dados:** SQLite  
- **ORM:** Flask-SQLAlchemy  
- **Migrações:** Flask-Migrate  
- **Autenticação:** Flask-Login  
- **Formulários:** Flask-WTF  
- **Segurança:** Werkzeug  
- **Análise de Dados e Gráficos:** Pandas, Matplotlib, NumPy  

---

## 📦 Como Rodar o Projeto

### 1. Clone o Repositório

```bash
git clone https://github.com/usuario/Fideliza.AI.projeto.git
cd Fideliza.AI.projeto
```

### 2. Crie e Ative o Ambiente Virtual

```bash
python -m venv venv
```

Ative o ambiente virtual:

- **Windows**:
  ```bash
  venv\Scripts\activate
  ```

- **macOS/Linux**:
  ```bash
  source venv/bin/activate
  ```

### 3. Crie o arquivo `requirements.txt`

Crie o arquivo `requirements.txt` com o conteúdo abaixo:

<details>
<summary><strong>Clique para expandir</strong></summary>

```
alembic==1.15.2
blinker==1.9.0
click==8.2.0
colorama==0.4.6
contourpy==1.3.2
cycler==0.12.1
dnspython==2.7.0
email_validator==2.2.0
Flask==3.1.1
Flask-Login==0.6.3
Flask-Migrate==4.1.0
Flask-SQLAlchemy==3.1.1
Flask-WTF==1.2.2
fonttools==4.58.0
greenlet==3.2.2
idna==3.10
itsdangerous==2.2.0
Jinja2==3.1.6
kiwisolver==1.4.8
Mako==1.3.10
MarkupSafe==3.0.2
matplotlib==3.10.3
numpy==2.2.6
packaging==25.0
pandas==2.2.3
pillow==11.2.1
pyparsing==3.2.3
python-dateutil==2.9.0.post0
python-dotenv==1.1.0
pytz==2025.2
setuptools==80.8.0
six==1.17.0
SQLAlchemy==2.0.40
typing_extensions==4.13.2
tzdata==2025.2
Werkzeug==3.1.3
wheel==0.45.1
WTForms==3.2.1
```

</details>

### 4. Instale as Dependências

```bash
pip install -r requirements.txt
```

### 5. Configure o Banco de Dados

```bash
flask db init                # Executar apenas na primeira vez
flask db migrate -m "Criando tabelas de usuários"
flask db upgrade
```

### 6. Execute a Aplicação

```bash
python app.py
```

Acesse no navegador: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 📂 Estrutura Básica do Projeto

```
Fideliza.AI.projeto/
├── app.py
├── models/
├── templates/
├── static/
├── migrations/
├── venv/
└── requirements.txt
```

---

## 🤝 Contribuições

Sinta-se à vontade para contribuir! Basta abrir uma *issue* ou enviar um *pull request* com sugestões de melhoria, correções ou novas funcionalidades.

---

## 📃 Licença

Este projeto está licenciado sob a **MIT License**. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
