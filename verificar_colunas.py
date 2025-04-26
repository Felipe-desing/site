import sqlite3

conn = sqlite3.connect('banco.db')
cursor = conn.cursor()
cursor.execute("PRAGMA table_info(usuarios)")
colunas = [col[1] for col in cursor.fetchall()]
print("Colunas da tabela usuarios:", colunas)
conn.close()