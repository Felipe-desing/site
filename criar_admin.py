import sqlite3
import bcrypt

# Senha que você quer para o administrador
senha = 'senha_admin'  # Mude para uma senha segura, se quiser
hashed = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

# Conectar ao banco
conn = sqlite3.connect('banco.db')
cursor = conn.cursor()

# Inserir administrador
try:
    cursor.execute('''
        INSERT INTO usuarios (nome, municipio, cpf, telefone, email, cnes, profissao, senha, status, is_admin)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('Admin', 'Município', '12345678901', '99999999999', 'admin@exemplo.com', '1234567', 'Administrador', hashed.decode('utf-8'), 'aprovado', True))
    conn.commit()
    print("Administrador criado com sucesso!")
    print(f"E-mail: admin@exemplo.com")
    print(f"Senha: {senha}")
except sqlite3.IntegrityError as e:
    print(f"Erro: E-mail ou CPF já existe no banco. Detalhes: {e}")
except sqlite3.OperationalError as e:
    print(f"Erro no banco de dados. Verifique se 'status' e 'is_admin' estão na tabela 'usuarios'. Detalhes: {e}")
finally:
    conn.close()