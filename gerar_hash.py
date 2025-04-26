import bcrypt

# Senha que você quer usar para o administrador
senha = 'senha_admin'  # Substitua por sua senha desejada

# Gerar o hash
hashed = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

# Exibir o hash
print(hashed.decode('utf-8'))