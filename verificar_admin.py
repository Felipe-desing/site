import sqlite3

conn = sqlite3.connect('banco.db')
cursor = conn.cursor()
cursor.execute("SELECT email, is_admin FROM usuarios WHERE email = 'admin@exemplo.com'")
usuario = cursor.fetchone()
if usuario:
    print(f"E-mail: {usuario[0]}, Is Admin: {usuario[1]}")
else:
    print("Administrador não encontrado.")
conn.close()