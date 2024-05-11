from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, MetaData, Table, Column, String, Integer, Boolean, select, func, DateTime
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.sql import select
import datetime
from datetime import datetime, timedelta
import dash
from dash import html, dcc, Input, Output, State, dash_table
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import pandas as pd
import base64
from dotenv import load_dotenv
import os
import io

# Carrega variáveis de ambiente
load_dotenv()

# Configuração inicial do Flask e SQLAlchemy
server = Flask(__name__, template_folder='templates', static_folder='static')
server.secret_key = os.getenv('FLASK_SECRET_KEY')

# Configuração da sessão para ser permanente e definir timeout
@server.before_request
def make_session_permanent():
    session.permanent = True
    server.permanent_session_lifetime = timedelta(minutes=30)

@server.before_request
def set_session_timeout():
    session.permanent = False


DATABASE_URL = os.getenv('DATABASE_URL')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
engine = create_engine(DATABASE_URL, connect_args={"sslmode": "require"})  # Assegura que a conexão use SSL
metadata = MetaData(bind=engine)
Session = sessionmaker(bind=engine)
db_session = scoped_session(Session)

# Tabela para armazenar dados dos arquivos
files_table = Table('uploaded_files', metadata,
                    Column('filename', String, primary_key=True),
                    Column('content', String),
                    Column('timestamp', DateTime, default=func.now()))

# Tabela para armazenar dados dos usuários
users_table = Table('users', metadata,
                    Column('email', String, primary_key=True),
                    Column('password_hash', String),
                    Column('superuser', Boolean, default=False))
# Cria as tabelas no banco de dados
metadata.create_all()

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = 'login'

@server.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/home')  # Redireciona se já estiver autenticado

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user_record = db_session.query(users_table).filter_by(email=email).first()
        if user_record:
            print(f"Usuário encontrado: {user_record.email}")  # Depuração
            if check_password_hash(user_record.password_hash, password):
                user = User(user_record.email)
                login_user(user)
                print("Login bem-sucedido")  # Depuração
                return redirect('/home')  # Redireciona para a home após login bem-sucedido
            else:
                print("Falha na verificação da senha")  # Depuração
        else:
            print("Usuário não encontrado")  # Depuração

        flash('Login Failed. Please check username and password.')

    return render_template('login.html')

# Classe de usuário
class User(UserMixin):
    def __init__(self, email, superuser=False):
        self.id = email
        self.superuser = superuser


@login_manager.user_loader
@login_manager.user_loader
def load_user(user_id):
    user_query = db_session.query(users_table).filter_by(email=user_id).first()
    if user_query:
        user = User(user_query.email, user_query.superuser)  # Adicione o atributo superuser aqui
        return user
    return None

@server.route('/logout')
def logout():
    logout_user()
    return ('/')


def is_admin():
    return current_user.is_authenticated and current_user.id == ADMIN_EMAIL

# Iniciar o aplicativo Dash
app = dash.Dash(__name__, server=server, external_stylesheets=[dbc.themes.BOOTSTRAP], suppress_callback_exceptions=True)

app.index_string = """<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
            <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
        {%css%}
    </head>
    <body style="background-color: black; color: #00ff00; font-family: monospace;">
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>"""


app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content', style={'backgroundColor': 'black'}),
    
])

# Callback de login modificado
@app.callback(
    Output('url', 'pathname'),
    [Input('login-button', 'n_clicks')],
    [State('email-input', 'value'), State('password-input', 'value')],
    prevent_initial_call=True
)
def handle_login(n_clicks, email, password):
    if n_clicks:
        user_record = db_session.query(users_table).filter_by(email=email).first()
        if user_record and check_password_hash(user_record.password_hash, password):
            user = User(user_record.email)
            login_user(user)
            return '/home'
        else:
            return '/login'
    return dash.no_update

@app.callback(
    Output('page-content', 'children'),
    [Input('url', 'pathname')]
)
def display_page(pathname):
    if not current_user.is_authenticated:
        return login_layout()

    if pathname in ['/home', '/']:
        return home_layout()

    return html.Div("You are not authorized to view this page", style={'color': 'red'})

def login_layout():
    return render_template('login.html')


@app.callback(Output('redirect', 'pathname'),
              [Input('logout-button', 'n_clicks')])
def logout_redirect(n_clicks):
    if n_clicks > 0:
        logout_user()
        return ('/')  # Redireciona para a tela de login após o logout
    return dash.no_update

def query_data():
    with engine.connect() as connection:
        df = pd.read_sql_query("SELECT * FROM uploaded_file", connection)
    return df

def load_file_data(filename):
    try:
        result = db_session.execute(select([files_table.c.content]).where(files_table.c.filename == filename)).fetchone()
        if result:
            # Tentativa de decodificação como ISO-8859-1, que é mais abrangente que ASCII
            try:
                return result[0].decode('ISO-8859-1')
            except AttributeError:
                # Se os dados já estiverem em string (não bytes), retorna diretamente
                return result[0]
        return None
    except Exception as e:
        print(f"Erro ao carregar dados do arquivo: {e}")
        return None





def home_layout():
    layout = [html.H3("Relatórios Cloud Server Promo 2023 e Cloud Server Promo 2024", style={'color': '#00ff00'})]
    session = db_session()

    # Área de upload, visível apenas para o superusuário
    if current_user.is_authenticated and current_user.superuser:
        layout.append(
            dcc.Upload(
                id='upload-data',
                children=html.Div(['Arraste e solte ou ', html.A('Selecione um Arquivo')]),
                style={
                    'width': '100%', 'height': '60px', 'lineHeight': '60px',
                    'borderWidth': '1px', 'borderStyle': 'dashed', 'borderRadius': '5px',
                    'textAlign': 'center', 'margin': '10px'
                },
                multiple=False
            )
        )
        layout.append(html.Div(id='output-data-upload'))

    # Carrega dados existentes do banco de dados
    try:
        results = session.execute(select([files_table])).fetchall()
        for result in results:
            file_data = load_file_data(result.filename)
            if file_data:
                df = pd.read_csv(io.StringIO(file_data), sep=';')
                dados_filtrados = df[df['Plano do Serviço'].str.contains('Cloud Server Promo 202[34]', na=False)]
                dados_plano = dados_filtrados[dados_filtrados['Tipo'] == 'Plano']
                dados_recursos = dados_filtrados[dados_filtrados['Tipo'] == 'Recursos']
                layout.append(html.Div([
                    html.H5(result.filename, style={'marginTop': '40px', 'marginBottom': '40px'}),
                    dbc.Tabs([
                        dbc.Tab(label='Assinaturas', children=[
                            dash_table.DataTable(
                                data=dados_plano.to_dict('records'),
                                style_cell={'backgroundColor': 'black', 'color': '#00ff00', 'border': '1px solid green'},
                                style_header={'backgroundColor': 'green', 'color': 'black', 'fontWeight': 'bold'},
                                style_table={'overflowX': 'auto'}
                            )
                        ], tab_style={'backgroundColor': 'black', 'color': 'green'},
                          active_tab_style={'backgroundColor': 'green', 'color': 'black'}),
                        dbc.Tab(label='Recursos', children=[
                            dash_table.DataTable(
                                data=dados_recursos.to_dict('records'),
                                style_cell={'backgroundColor': 'black', 'color': '#00ff00', 'border': '1px solid green'},
                                style_header={'backgroundColor': 'green', 'color': 'black', 'fontWeight': 'bold'},
                                style_table={'overflowX': 'auto'}
                            )
                        ], tab_style={'backgroundColor': 'black', 'color': 'green'},
                          active_tab_style={'backgroundColor': 'green', 'color': 'black'}),
                    ], style={'marginBottom': '20px'}),
                ]))
    except Exception as e:
        layout.append(html.Div(str(e)))  # Exibe o erro para diagnóstico
    finally:
        session.close()  # Fecha a sessão do banco
    layout.append(
        html.Footer([
            html.P("por Fernando Damásio", style={'fontSize': 'small', 'textAlign': 'center'}),
            html.Button('Sair', id='logout-button', n_clicks=0, style={'backgroundColor': '#00ff00', 'color': 'black','float': 'right'}),
        ], style={
            'width': '100%', 'backgroundColor': 'black', 'color': '#00ff00', 'padding': '10px', 'borderTop': '1px solid green'
        }),              
    )

    return html.Div(layout, style={'backgroundColor': 'black', 'color': '#00ff00'})

    
# Definir layout do Dash app
app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content')
])


@app.callback(
    Output('output-data-upload', 'children'),
    [Input('upload-data', 'contents')],
    [State('upload-data', 'filename'), State('upload-data', 'last_modified'), State('output-data-upload', 'children')]
)
def update_output(contents, filename, last_modified, existing_children):
    if contents :
        content_type, content_string = contents.split(',') if ',' in contents else (None, None)
        if content_string:
            decoded = base64.b64decode(content_string)
            df = pd.read_csv(io.StringIO(decoded.decode('ISO-8859-1')), sep=';')
            file_data = decoded.decode('ISO-8859-1')
            dados_filtrados = df[df['Plano do Serviço'].str.contains('Cloud Server Promo 202[34]', na=False)]
            
            # Especificando colunas para a aba "Plano"
            colunas_plano = [
                {'name': 'ID Cliente', 'id': 'ID Cliente'},
                {'name': 'Cliente', 'id': 'Cliente'},
                {'name': 'CLE', 'id': 'CLE'},
                {'name': 'Método Pagamento', 'id': 'Método Pagamento'},
                {'name': 'ID Assinatura', 'id': 'ID Assinatura'},
                {'name': 'Tipo', 'id': 'Tipo'},
                {'name': 'Período', 'id': 'Período'},
                {'name': 'Status Assinatura', 'id': 'Status Assinatura'},
                {'name': 'ID Plano', 'id': 'ID Plano'},
                {'name': 'Plano do Serviço', 'id': 'Plano do Serviço'},
                {'name': 'SKU', 'id': 'SKU'},
                {'name': 'Assinatura', 'id': 'Assinatura/Recurso'},
                {'name': 'Preço Unitário', 'id': 'Preço Unitário'},
                {'name': 'Incluso', 'id': 'Incluso'},
                {'name': 'Data do Pedido', 'id': 'Data do Pedido'},
                {'name': 'Data de Provisionamento', 'id': 'Data de Provisionamento'},
                {'name': 'Data desativação', 'id': 'Data desativação'},
                {'name': 'Data de bloqueio', 'id': 'Data de bloqueio'},
                {'name': 'Tempo bloqueado(dias)', 'id': 'Tempo bloqueado(dias)'},
                {'name': 'Cidade', 'id': 'Cidade'},
                {'name': 'UF', 'id': 'UF'},
                {'name': 'Contato Administrativo', 'id': 'Contato Administrativo'},
                {'name': 'Telefone Administrativo', 'id': 'Telefone Administrativo'},
                {'name': 'Desativaçao Motivo', 'id': 'Desativaçao Motivo'},
                {'name': 'Desativaçao Comentário', 'id': 'Desativaçao Comentário'}
            ]
            dados_plano = dados_filtrados[dados_filtrados['Tipo'] == 'Plano']
            
            # Especificando colunas para a aba "Recursos"
            colunas_recursos = [
            {'name': 'ID Cliente', 'id': 'ID Cliente'},
            {'name': 'ID Assinatura', 'id': 'ID Assinatura'},
            {'name': 'Período Contratual', 'id': 'Período Contratual'},
            {'name': 'ID Recursos', 'id': 'ID Recursos'},
            {'name': 'ID Plano', 'id': 'ID Plano'},
            {'name': 'Plano do Serviço', 'id': 'Plano do Serviço'},
            {'name': 'SKU', 'id': 'SKU'},
            {'name': 'Recurso', 'id': 'Assinatura/Recurso'},
            {'name': 'Preço Unitário', 'id': 'Preço Unitário'},
            #{'name': 'Incluso', 'id': 'Incluso'},
            {'name': 'Adicional', 'id': 'Adicional'},
            {'name': 'Quantidade Atual', 'id': 'Quantidade Atual'},
            {'name': 'Consumo', 'id': 'Consumo'},
            {'name': 'Preço Total', 'id': 'Preço Total'},
            {'name': 'SUBSCR_UF', 'id': 'SUBSCR_UF'}
        ]
            dados_recursos = dados_filtrados[dados_filtrados['Tipo'] == 'Recursos']
            
            new_file = files_table.insert().values(
                filename=filename, content=file_data, timestamp=datetime.utcnow().isoformat()
            )
            db_session.execute(new_file)
            db_session.commit()

            # Construindo novos componentes HTML para serem exibidos
            new_upload = html.Div([
                html.H5(filename),
                html.H6(datetime.fromtimestamp(int(last_modified)).strftime('%Y-%m-%d %H:%M:%S')),
                dbc.Tabs([
                    dbc.Tab(label='Assinaturas', children=[
                        html.Div([
                            html.H1("Dados do Plano", style={'color': '#00ff00'}),
                            dash_table.DataTable(
                                data=dados_plano.to_dict('records'),
                                columns=colunas_plano,
                                style_cell={'backgroundColor': 'black', 'color': '#00ff00', 'border': '1px solid green'},
                                style_header={'backgroundColor': 'green', 'color': 'black', 'fontWeight': 'bold'},
                                style_table={'overflowX': 'auto'}
                            )
                        ])
                    ], tab_style={'backgroundColor': 'black', 'color': 'green'},
                          active_tab_style={'backgroundColor': 'green', 'color': 'black'}),
                    dbc.Tab(label='Recursos', children=[
                        html.Div([
                            html.H1("Dados de Recursos", style={'color': '#00ff00'}),
                            dash_table.DataTable(
                                data=dados_recursos.to_dict('records'),
                                columns=colunas_recursos,
                                style_cell={'backgroundColor': 'black', 'color': '#00ff00', 'border': '1px solid green'},
                                style_header={'backgroundColor': 'green', 'color': 'black', 'fontWeight': 'bold'},
                                style_table={'overflowX': 'auto'}
                            )
                        ])
                    ])
                ])
            ])
            return [new_upload] + (existing_children if existing_children else [])
    return existing_children   # Return existing content if not superuser or no new data
  # Retornar o conteúdo existente se não for superusuário ou não houver novos dados


@app.callback(
    Output('view-uploaded-data', 'children'),
    [Input('url', 'pathname')]
)
def update_view(pathname):
    if pathname == '/home':
        # Load files from database and display
        query = select([files_table])
        results = db_session.execute(query).fetchall()
        children = []
        for result in results:
            children.append(html.Div([
                html.H5(result['filename']),
                html.P(result['timestamp'])
            ]))
        return html.Div(children)
    return []

def parse_contents(contents, filename, date):
    content_type, content_string = contents.split(',')
    decoded = base64.b64decode(content_string)

    try:
        df = pd.read_csv(io.StringIO(decoded.decode('utf-8')), sep=';')
    except UnicodeDecodeError:
        df = pd.read_csv(io.StringIO(decoded.decode('ISO-8859-1')), sep=';')

    # Aplica filtros e seleciona colunas para cada aba
    dados_filtrados = df[df['Plano do Serviço'].str.contains('Cloud Server Promo 202[34]', na=False)]
    dados_plano = dados_filtrados[dados_filtrados['Tipo'] == 'Plano']
    dados_recursos = dados_filtrados[dados_filtrados['Tipo'] == 'Recursos']

    # Especifica as colunas diretamente para cada DataTable
    colunas_plano = [
                {'name': 'ID Cliente', 'id': 'ID Cliente'},
                {'name': 'Cliente', 'id': 'Cliente'},
                {'name': 'CLE', 'id': 'CLE'},
                {'name': 'Método Pagamento', 'id': 'Método Pagamento'},
                {'name': 'ID Assinatura', 'id': 'ID Assinatura'},
                {'name': 'Tipo', 'id': 'Tipo'},
                {'name': 'Período', 'id': 'Período'},
                {'name': 'Status Assinatura', 'id': 'Status Assinatura'},
                {'name': 'ID Plano', 'id': 'ID Plano'},
                {'name': 'Plano do Serviço', 'id': 'Plano do Serviço'},
                {'name': 'SKU', 'id': 'SKU'},
                {'name': 'Assinatura', 'id': 'Assinatura/Recurso'},
                {'name': 'Preço Unitário', 'id': 'Preço Unitário'},
                {'name': 'Incluso', 'id': 'Incluso'},
                {'name': 'Data do Pedido', 'id': 'Data do Pedido'},
                {'name': 'Data de Provisionamento', 'id': 'Data de Provisionamento'},
                {'name': 'Data desativação', 'id': 'Data desativação'},
                {'name': 'Data de bloqueio', 'id': 'Data de bloqueio'},
                {'name': 'Tempo bloqueado(dias)', 'id': 'Tempo bloqueado(dias)'},
                {'name': 'Cidade', 'id': 'Cidade'},
                {'name': 'UF', 'id': 'UF'},
                {'name': 'Contato Administrativo', 'id': 'Contato Administrativo'},
                {'name': 'Telefone Administrativo', 'id': 'Telefone Administrativo'},
                {'name': 'Desativaçao Motivo', 'id': 'Desativaçao Motivo'},
                {'name': 'Desativaçao Comentário', 'id': 'Desativaçao Comentário'}
            ]
    dados_plano = dados_filtrados[dados_filtrados['Tipo'] == 'Plano']
            
            # Especificando colunas para a aba "Recursos"
    colunas_recursos = [
            {'name': 'ID Cliente', 'id': 'ID Cliente'},
            {'name': 'ID Assinatura', 'id': 'ID Assinatura'},
            {'name': 'Período Contratual', 'id': 'Período Contratual'},
            {'name': 'ID Recursos', 'id': 'ID Recursos'},
            {'name': 'ID Plano', 'id': 'ID Plano'},
            {'name': 'Plano do Serviço', 'id': 'Plano do Serviço'},
            {'name': 'SKU', 'id': 'SKU'},
            {'name': 'Recurso', 'id': 'Assinatura/Recurso'},
            {'name': 'Preço Unitário', 'id': 'Preço Unitário'},
            #{'name': 'Incluso', 'id': 'Incluso'},
            {'name': 'Adicional', 'id': 'Adicional'},
            {'name': 'Quantidade Atual', 'id': 'Quantidade Atual'},
            {'name': 'Consumo', 'id': 'Consumo'},
            {'name': 'Preço Total', 'id': 'Preço Total'},
            {'name': 'SUBSCR_UF', 'id': 'SUBSCR_UF'}
        ]
    dados_recursos = dados_filtrados[dados_filtrados['Tipo'] == 'Recursos']

    return html.Div([
        html.H5(filename),
        html.H6(datetime.fromtimestamp(int(date)).strftime('%Y-%m-%d %H:%M:%S')),
        dbc.Tabs([
            dbc.Tab(label='Assinaturas', children=[
                html.Div([
                    html.H1("Dados do Plano", style={'color': '#00ff00'}),
                    dash_table.DataTable(
                        data=dados_plano.to_dict('records'),
                        columns=colunas_plano,
                        style_cell={'backgroundColor': 'black', 'color': '#00ff00', 'border': '1px solid green'},
                        style_header={'backgroundColor': 'green', 'color': 'black', 'fontWeight': 'bold'},
                        style_table={'overflowX': 'auto'}
                    )
                ])
            ]),
            dbc.Tab(label='Recursos', children=[
                html.Div([
                    html.H1("Dados de Recursos", style={'color': '#00ff00'}),
                    dash_table.DataTable(
                        data=dados_recursos.to_dict('records'),
                        columns=colunas_recursos,
                        style_cell={'backgroundColor': 'black', 'color': '#00ff00', 'border': '1px solid green'},
                        style_header={'backgroundColor': 'green', 'color': 'black', 'fontWeight': 'bold'},
                        style_table={'overflowX': 'auto'}
                    )
                ], tab_style={'backgroundColor': 'black', 'color': 'green'},
                          tab_class_name='custom-tab', active_tab_style={'backgroundColor': 'green', 'color': 'black'}),
            ])
        ])
    ])


if __name__ == '__main__':
    app.run_server(debug=True)

def check_database_contents():
        session = db_session()  # Abre uma sessão de banco de dados
        try:
            results = session.execute(select([files_table])).fetchall()
            for result in results:
                print(result)  # Imprime cada registro para depuração
        finally:
            session.close()  # Certifique-se de fechar a sessão após a consulta

    # Chamada da função para verificar o banco
check_database_contents()