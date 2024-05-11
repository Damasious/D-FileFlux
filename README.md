# D-FileFlux

D-FileFlux é um sistema de gerenciamento de autenticação e arquivos, permitindo que superusuários como administradores gerenciem arquivos e controles de acesso de usuários.

## Funcionalidades

- **Autenticação de Usuários**: Interface de login segura para autenticação de usuários.
- **Gerenciamento de Arquivos**: Permite ao superusuário realizar o upload e gerenciar arquivos.

## Tecnologias Utilizadas

- Python
- Flask para o servidor web
- HTML/CSS para a interface do usuário
- JavaScript para interatividade da página

## Estrutura do Projeto

```plaintext
D-FileFlux/
│
├── server.py                 # Arquivo principal do servidor Flask
│
├── templates/                # Pasta contendo os templates HTML
│   └── login.html            # Template de login
│
├── static/                   # Pasta para arquivos estáticos
│   ├── css/                  # CSS para estilização
│   │   └── style.css         
│   │
│   └── js/                   # JavaScript para funcionalidades
│       └── login.js
├── .gitignore
├── README.md          
├── .env                      # Configurações de ambiente
└── requirements.txt          # Dependências do Python
