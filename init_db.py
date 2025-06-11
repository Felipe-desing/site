import sqlite3

def criar_banco():
    try:
        # Conectando ao banco de dados
        conn = sqlite3.connect('banco.db')
        cursor = conn.cursor()
        print("Conectado ao banco de dados 'banco.db'.")

        # Criando a tabela de usuários
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            municipio TEXT NOT NULL,
            cpf TEXT NOT NULL,
            telefone TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            cnes TEXT NOT NULL,
            profissao TEXT NOT NULL,
            senha TEXT NOT NULL,
            approved INTEGER DEFAULT 0,
            ativo INTEGER DEFAULT 1,
            is_admin INTEGER DEFAULT 0,
            is_super_admin INTEGER DEFAULT 0,  -- Novo campo para perfil estadual
            role TEXT DEFAULT 'municipal'     -- Campo existente
        )
        ''')
        print("Tabela 'usuarios' verificada/criada.")

        # Migração: profissao
        try:
            cursor.execute('ALTER TABLE usuarios ADD COLUMN profissao TEXT')
            print("Coluna 'profissao' adicionada à tabela 'usuarios'.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("Coluna 'profissao' já existe na tabela 'usuarios'.")
            else:
                print(f"Erro ao adicionar coluna 'profissao': {str(e)}")

        # Migração: approved
        try:
            cursor.execute('ALTER TABLE usuarios ADD COLUMN approved INTEGER DEFAULT 0')
            print("Coluna 'approved' adicionada à tabela 'usuarios'.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("Coluna 'approved' já existe na tabela 'usuarios'.")
            else:
                print(f"Erro ao adicionar coluna 'approved': {str(e)}")

        # Migração: ativo
        try:
            cursor.execute('ALTER TABLE usuarios ADD COLUMN ativo INTEGER DEFAULT 1')
            print("Coluna 'ativo' adicionada à tabela 'usuarios'.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("Coluna 'ativo' já existe na tabela 'usuarios'.")
            else:
                print(f"Erro ao adicionar coluna 'ativo': {str(e)}")

        # Migração: is_admin
        try:
            cursor.execute('ALTER TABLE usuarios ADD COLUMN is_admin INTEGER DEFAULT 0')
            print("Coluna 'is_admin' adicionada à tabela 'usuarios'.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("Coluna 'is_admin' já existe na tabela 'usuarios'.")
            else:
                print(f"Erro ao adicionar coluna 'is_admin': {str(e)}")

        # Migração: is_super_admin
        try:
            cursor.execute('ALTER TABLE usuarios ADD COLUMN is_super_admin INTEGER DEFAULT 0')
            print("Coluna 'is_super_admin' adicionada à tabela 'usuarios'.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("Coluna 'is_super_admin' já existe na tabela 'usuarios'.")
            else:
                print(f"Erro ao adicionar coluna 'is_super_admin': {str(e)}")

        # Migração: role
        try:
            cursor.execute('ALTER TABLE usuarios ADD COLUMN role TEXT DEFAULT "municipal"')
            print("Coluna 'role' adicionada à tabela 'usuarios'.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("Coluna 'role' já existe na tabela 'usuarios'.")
            else:
                print(f"Erro ao adicionar coluna 'role': {str(e)}")

        # Migração: approved (status para approved)
        try:
            cursor.execute("PRAGMA table_info(usuarios)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'status' in columns and 'approved' not in columns:
                cursor.execute('ALTER TABLE usuarios RENAME COLUMN status TO approved')
                print("Coluna 'status' renomeada para 'approved'.")
                cursor.execute('UPDATE usuarios SET approved = 1 WHERE approved = "aprovado"')
                cursor.execute('UPDATE usuarios SET approved = 0 WHERE approved = "pendente"')
                print("Valores de 'status' convertidos para 'approved' (0 ou 1).")
        except sqlite3.OperationalError as e:
            print(f"Erro ao renomear coluna 'status': {str(e)}")

        # Salvando e fechando a conexão
        conn.commit()
        print("Banco de dados e tabelas 'usuarios', 'calculos' e 'acoes_administrativas' inicializados com sucesso.")

    except sqlite3.Error as e:
        print(f"Erro ao configurar o banco de dados: {str(e)}")
        raise
    finally:
        conn.close()
        print("Conexão com o banco de dados fechada.")

if __name__ == "__main__":
    criar_banco()