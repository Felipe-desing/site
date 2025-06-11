import bcrypt

# Senha para o administrador
senha = 'senha_admin'

# Gerar o hash
hashed = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

# Exibir o hash
print(hashed.decode('utf-8'))