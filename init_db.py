import sqlite3

def criar_banco():
    try:
        # Conectando ao banco de dados (será criado se não existir)
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
            status TEXT DEFAULT 'pendente',
            is_admin BOOLEAN DEFAULT FALSE
        )
        ''')
        print("Tabela 'usuarios' verificada/criada.")

        # Migração: Adicionar a coluna profissao se ela não existir
        try:
            cursor.execute('ALTER TABLE usuarios ADD COLUMN profissao TEXT')
            print("Coluna 'profissao' adicionada à tabela 'usuarios'.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("Coluna 'profissao' já existe na tabela 'usuarios'.")
            else:
                print(f"Erro ao adicionar coluna 'profissao': {str(e)}")

        # Migração: Adicionar a coluna status se ela não existir
        try:
            cursor.execute('ALTER TABLE usuarios ADD COLUMN status TEXT DEFAULT "pendente"')
            print("Coluna 'status' adicionada à tabela 'usuarios'.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("Coluna 'status' já existe na tabela 'usuarios'.")
            else:
                print(f"Erro ao adicionar coluna 'status': {str(e)}")

        # Migração: Adicionar a coluna is_admin se ela não existir
        try:
            cursor.execute('ALTER TABLE usuarios ADD COLUMN is_admin BOOLEAN DEFAULT FALSE')
            print("Coluna 'is_admin' adicionada à tabela 'usuarios'.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("Coluna 'is_admin' já existe na tabela 'usuarios'.")
            else:
                print(f"Erro ao adicionar coluna 'is_admin': {str(e)}")

        # Criando a tabela de cálculos
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS calculos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            codigo_ficha TEXT NOT NULL UNIQUE,
            nome_gestante TEXT NOT NULL,
            data_nasc TEXT NOT NULL,
            telefone TEXT NOT NULL,
            municipio TEXT NOT NULL,
            ubs TEXT NOT NULL,
            acs TEXT NOT NULL,
            periodo_gestacional TEXT NOT NULL,
            data_envio TEXT NOT NULL,
            pontuacao_total INTEGER NOT NULL,
            classificacao_risco TEXT NOT NULL,
            imc REAL,
            caracteristicas TEXT,
            avaliacao_nutricional TEXT,
            comorbidades TEXT,
            historia_obstetrica TEXT,
            condicoes_gestacionais TEXT,
            profissional TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES usuarios (id)
        )
        ''')
        print("Tabela 'calculos' verificada/criada.")

        # Migração: Renomear colunas gestacoes_previas e gestacao_atual, se existirem
        try:
            cursor.execute("PRAGMA table_info(calculos)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'gestacoes_previas' in columns and 'historia_obstetrica' not in columns:
                cursor.execute('''
                    ALTER TABLE calculos RENAME COLUMN gestacoes_previas TO historia_obstetrica
                ''')
                print("Coluna 'gestacoes_previas' renomeada para 'historia_obstetrica'.")
            
            if 'gestacao_atual' in columns and 'condicoes_gestacionais' not in columns:
                cursor.execute('''
                    ALTER TABLE calculos RENAME COLUMN gestacao_atual TO condicoes_gestacionais
                ''')
                print("Coluna 'gestacao_atual' renomeada para 'condicoes_gestacionais'.")

        except sqlite3.OperationalError as e:
            print(f"Erro ao renomear colunas: {str(e)}")

        # Verificar registros inválidos em calculos
        cursor.execute('SELECT COUNT(*) FROM calculos WHERE municipio IS NULL OR nome_gestante IS NULL')
        invalid_records = cursor.fetchone()[0]
        if invalid_records > 0:
            print(f"Aviso: Encontrados {invalid_records} registros em 'calculos' com municipio ou nome_gestante NULL.")

        # Salvando e fechando a conexão
        conn.commit()
        print("Banco de dados e tabelas 'usuarios' e 'calculos' inicializados com sucesso.")

    except sqlite3.Error as e:
        print(f"Erro ao configurar o banco de dados: {str(e)}")
        raise
    finally:
        conn.close()
        print("Conexão com o banco de dados fechada.")

if __name__ == "__main__":
    criar_banco()