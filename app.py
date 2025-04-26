from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
import json
import re
import uuid
from datetime import datetime
import bcrypt
from init_db import criar_banco

app = Flask(__name__)
app.secret_key = 'chave_secreta_segura'

# Inicializar o banco de dados
criar_banco()

def get_db_connection():
    conn = sqlite3.connect('banco.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, senha, status, is_admin FROM usuarios WHERE email = ?", (email,))
        usuario = cursor.fetchone()
        conn.close()

        if usuario:
            try:
                # Converter a senha do banco (string) para bytes
                senha_banco = usuario['senha'].encode('utf-8') if isinstance(usuario['senha'], str) else usuario['senha']
                print(f"Tentando verificar senha para email={email}, senha_banco={senha_banco[:10]}... (primeiros 10 caracteres)")
                if bcrypt.checkpw(senha.encode('utf-8'), senha_banco):
                    if usuario['status'] == 'pendente':
                        flash('Seu cadastro está aguardando aprovação.', 'warning')
                        return redirect(url_for('login'))
                    elif usuario['status'] == 'rejeitado':
                        flash('Seu cadastro foi rejeitado.', 'danger')
                        return redirect(url_for('login'))
                    session['user_id'] = usuario['id']
                    session['is_admin'] = usuario['is_admin']
                    print(f"Login bem-sucedido: user_id={session['user_id']}, email={email}, is_admin={usuario['is_admin']}")
                    flash('Login realizado com sucesso!', 'success')
                    return redirect(url_for('calculadora'))
                else:
                    print(f"Senha incorreta para email={email}")
                    flash('Email ou senha inválidos.', 'danger')
                    return redirect(url_for('login'))
            except ValueError as e:
                print(f"Erro ao verificar senha para email={email}: {str(e)}")
                flash('Erro na verificação da senha. Contate o administrador.', 'danger')
                return redirect(url_for('login'))
        else:
            print(f"Usuário não encontrado para email={email}")
            flash('Email ou senha inválidos.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    nome = request.form['nome']
    municipio = request.form['municipio']
    cpf = request.form['cpf']
    telefone = request.form['telefone']
    email = request.form['email']
    cnes = request.form['cnes']
    profissao = request.form['profissao']
    senha = request.form['senha']
    confirmar = request.form['confirmar']

    if senha != confirmar:
        flash('As senhas não coincidem.', 'warning')
        return redirect(url_for('login'))

    # Gerar hash da senha e converter para string
    hashed_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    print(f"Gerando hash para email={email}: hashed_senha={hashed_senha[:10]}... (primeiros 10 caracteres)")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO usuarios (nome, municipio, cpf, telefone, email, cnes, profissao, senha, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pendente')
        ''', (nome, municipio, cpf, telefone, email, cnes, profissao, hashed_senha))
        conn.commit()
        print(f"Usuário cadastrado: email={email}, profissao={profissao}, status=pendente")
        conn.close()

        flash('Cadastro realizado com sucesso! Aguardando aprovação.', 'success')
        return redirect(url_for('login'))

    except sqlite3.IntegrityError:
        print(f"Erro: E-mail ou CPF já cadastrado para email={email}")
        flash('Este e-mail ou CPF já está cadastrado.', 'danger')
        return redirect(url_for('login'))

@app.route('/admin/approve', methods=['GET', 'POST'])
def admin_approve():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        user_id = request.form['user_id']
        action = request.form['action']
        new_status = 'aprovado' if action == 'approve' else 'rejeitado'
        cursor.execute('UPDATE usuarios SET status = ? WHERE id = ?', (new_status, user_id))
        if cursor.rowcount == 0:
            print(f"Erro: Nenhum usuário atualizado para user_id={user_id}")
            flash('Erro ao atualizar o cadastro.', 'danger')
        else:
            print(f"Usuário {user_id} atualizado para status={new_status}")
            flash(f'Cadastro {new_status} com sucesso.', 'success')
        conn.commit()

    cursor.execute('SELECT id, nome, email, profissao, municipio FROM usuarios WHERE status = "pendente"')
    pending_users = cursor.fetchall()
    conn.close()

    return render_template('admin_approve.html', pending_users=pending_users)

@app.route('/admin/senha')
def admin_senha():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('login'))

    print(f"Renderizando admin_senha.html para user_id={session['user_id']}")
    return render_template('admin_senha.html')

@app.route('/admin/reset_senha', methods=['POST'])
def admin_reset_senha():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('login'))

    email = request.form.get('email')
    nova_senha = request.form.get('nova_senha')

    if not email or not nova_senha:
        flash('E-mail e nova senha são obrigatórios.', 'danger')
        print(f"Erro: Campos obrigatórios vazios - email={email}, nova_senha={'<preenchida>' if nova_senha else '<vazia>'}")
        return redirect(url_for('admin_senha'))

    if len(nova_senha) < 6:
        flash('A nova senha deve ter pelo menos 6 caracteres.', 'danger')
        print(f"Erro: Senha muito curta para email={email}")
        return redirect(url_for('admin_senha'))

    # Gerar hash da nova senha
    hashed = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    print(f"Gerando novo hash para email={email}: hashed_senha={hashed[:10]}... (primeiros 10 caracteres)")

    # Atualizar no banco
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET senha = ? WHERE email = ?", (hashed, email))
    
    if cursor.rowcount > 0:
        conn.commit()
        flash(f'Senha do usuário {email} redefinida com sucesso!', 'success')
        print(f"Senha redefinida com sucesso para email={email}")
    else:
        flash(f'Erro: E-mail {email} não encontrado.', 'danger')
        print(f"Erro: E-mail não encontrado: {email}")
    
    conn.close()
    return redirect(url_for('admin_senha'))

@app.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.form.get('email')
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    # Validações
    if not all([email, old_password, new_password, confirm_password]):
        flash('Todos os campos são obrigatórios.', 'danger')
        print(f"Erro: Campos obrigatórios vazios - email={email}, old_password={'<preenchida>' if old_password else '<vazia>'}, "
              f"new_password={'<preenchida>' if new_password else '<vazia>'}, confirm_password={'<preenchida>' if confirm_password else '<vazia>'}")
        return redirect(url_for('login'))

    if new_password != confirm_password:
        flash('As novas senhas não coincidem.', 'warning')
        print(f"Erro: Novas senhas não coincidem para email={email}")
        return redirect(url_for('login'))

    if len(new_password) < 6:
        flash('A nova senha deve ter pelo menos 6 caracteres.', 'danger')
        print(f"Erro: Nova senha muito curta para email={email}")
        return redirect(url_for('login'))

    # Verificar usuário e senha antiga
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, senha, is_admin FROM usuarios WHERE email = ?", (email,))
    usuario = cursor.fetchone()

    if not usuario:
        flash('E-mail não encontrado.', 'danger')
        print(f"Erro: E-mail não encontrado: {email}")
        conn.close()
        return redirect(url_for('login'))

    try:
        senha_banco = usuario['senha'].encode('utf-8') if isinstance(usuario['senha'], str) else usuario['senha']
        if not bcrypt.checkpw(old_password.encode('utf-8'), senha_banco):
            flash('Senha antiga incorreta.', 'danger')
            print(f"Erro: Senha antiga incorreta para email={email}")
            conn.close()
            return redirect(url_for('login'))
    except ValueError as e:
        flash('Erro na verificação da senha. Contate o administrador.', 'danger')
        print(f"Erro ao verificar senha antiga para email={email}: {str(e)}")
        conn.close()
        return redirect(url_for('login'))

    # Gerar hash da nova senha
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    print(f"Gerando novo hash para email={email}: hashed_senha={hashed[:10]}... (primeiros 10 caracteres)")

    # Atualizar senha no banco
    try:
        cursor.execute("UPDATE usuarios SET senha = ? WHERE email = ?", (hashed, email))
        if cursor.rowcount > 0:
            conn.commit()
            flash('Senha redefinida com sucesso! Faça login com a nova senha.', 'success')
            print(f"Senha redefinida com sucesso para email={email}")
        else:
            flash('Erro ao redefinir a senha. Tente novamente.', 'danger')
            print(f"Erro: Nenhuma linha afetada ao atualizar senha para email={email}")
    except sqlite3.Error as e:
        flash('Erro no banco de dados. Contate o administrador.', 'danger')
        print(f"Erro no banco de dados ao redefinir senha para email={email}: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

    return redirect(url_for('login'))

@app.route('/calculadora')
def calculadora():
    if 'user_id' not in session:
        flash('Por favor, faça login para acessar a calculadora.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT status FROM usuarios WHERE id = ?', (session['user_id'],))
    usuario = cursor.fetchone()
    conn.close()
    
    if not usuario or usuario['status'] != 'aprovado':
        flash('Acesso negado. Seu cadastro não foi aprovado.', 'danger')
        session.pop('user_id', None)
        session.pop('is_admin', None)
        return redirect(url_for('login'))
    
    print(f"Renderizando calculadora.html para user_id={session['user_id']}")
    return render_template('calculadora.html')

@app.route('/verificar_ficha', methods=['POST'])
def verificar_ficha():
    if 'user_id' not in session:
        return jsonify({'error': 'Por favor, faça login.'}), 401

    codigo_ficha = request.form.get('codigo_ficha')
    if not codigo_ficha:
        return jsonify({'error': 'Código da ficha é obrigatório.'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT user_id FROM calculos WHERE codigo_ficha = ?', (codigo_ficha,))
        ficha = cursor.fetchone()
        conn.close()

        if ficha:
            if ficha['user_id'] == session['user_id']:
                return jsonify({'exists': True, 'can_edit': True})
            else:
                return jsonify({'exists': True, 'can_edit': False, 'message': 'Você não tem permissão para editar esta ficha.'})
        else:
            return jsonify({'exists': False, 'message': 'Ficha não encontrada.'})

    except Exception as e:
        print(f"Erro ao verificar ficha: {str(e)}")
        return jsonify({'error': f'Erro ao verificar ficha: {str(e)}'}), 500

@app.route('/carregar_ficha', methods=['POST'])
def carregar_ficha():
    if 'user_id' not in session:
        flash('Por favor, faça login.', 'danger')
        return redirect(url_for('login'))

    codigo_ficha = request.form.get('codigo_ficha')
    if not codigo_ficha:
        flash('Por favor, insira o código da ficha.', 'danger')
        return redirect(url_for('calculadora'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        print(f"Tentando carregar ficha: codigo_ficha={codigo_ficha}, user_id={session['user_id']}")
        cursor.execute('''
            SELECT * FROM calculos WHERE codigo_ficha = ? AND user_id = ?
        ''', (codigo_ficha, session['user_id']))
        ficha = cursor.fetchone()

        cursor.execute('SELECT user_id, nome_gestante FROM calculos WHERE codigo_ficha = ?', (codigo_ficha,))
        ficha_existente = cursor.fetchone()
        if ficha_existente:
            print(f"Ficha encontrada no banco: codigo_ficha={codigo_ficha}, user_id={ficha_existente['user_id']}, nome_gestante={ficha_existente['nome_gestante']}")
        else:
            print(f"Nenhuma ficha encontrada com codigo_ficha={codigo_ficha}")

        conn.close()

        if ficha:
            ficha_dict = dict(ficha)
            try:
                ficha_dict['caracteristicas'] = json.loads(ficha['caracteristicas'] or '[]')
                ficha_dict['avaliacao_nutricional'] = json.loads(ficha['avaliacao_nutricional'] or '[]')
                ficha_dict['comorbidades'] = json.loads(ficha['comorbidades'] or '[]')
                ficha_dict['historia_obstetrica'] = json.loads(ficha['historia_obstetrica'] or '[]')
                ficha_dict['condicoes_gestacionais'] = json.loads(ficha['condicoes_gestacionais'] or '[]')
                print(f"Ficha carregada: nome_gestante={ficha_dict['nome_gestante']}, caracteristicas={ficha_dict['caracteristicas']}")
            except json.JSONDecodeError as e:
                print(f"Erro ao desserializar JSON: {e}")
                ficha_dict['caracteristicas'] = []
                ficha_dict['avaliacao_nutricional'] = []
                ficha_dict['comorbidades'] = []
                ficha_dict['historia_obstetrica'] = []
                ficha_dict['condicoes_gestacionais'] = []

            return render_template('calculadora.html', ficha=ficha_dict)
        else:
            if ficha_existente:
                flash('Você não tem permissão para acessar esta ficha.', 'danger')
            else:
                flash('Ficha não encontrada.', 'danger')
            return redirect(url_for('calculadora'))

    except sqlite3.OperationalError as e:
        print(f"Erro no banco de dados: {str(e)}")
        flash(f'Erro no banco de dados: {str(e)}', 'danger')
        return redirect(url_for('calculadora'))

@app.route('/salvar_calculadora', methods=['POST'])
def salvar_calculadora():
    if 'user_id' not in session:
        flash('Por favor, faça login para salvar os dados.', 'danger')
        return redirect(url_for('login'))

    try:
        nome_gestante = request.form.get('nome_gestante')
        data_nasc = request.form.get('data_nasc')
        telefone = request.form.get('telefone')
        municipio = request.form.get('municipio')
        ubs = request.form.get('ubs')
        acs = request.form.get('acs')
        periodo_gestacional = request.form.get('periodo_gestacional')
        data_envio = request.form.get('data_envio', datetime.now().strftime('%d/%m/%Y'))
        pontuacao_total = request.form.get('pontuacao_total', '0')
        classificacao_risco = request.form.get('classificacao_risco', 'Risco Habitual')
        imc = request.form.get('imc', None)

        caracteristicas = request.form.getlist('caracteristicas')
        avaliacao_nutricional = request.form.getlist('avaliacao_nutricional')
        comorbidades = request.form.getlist('comorbidades')
        historia_obstetrica = request.form.getlist('historia_obstetrica')
        condicoes_gestacionais = request.form.getlist('condicoes_gestacionais')

        print(f"Dados recebidos para salvar: user_id={session['user_id']}, "
              f"nome_gestante='{nome_gestante}', data_nasc='{data_nasc}', "
              f"telefone='{telefone}', municipio='{municipio}', ubs='{ubs}', "
              f"acs='{acs}', periodo_gestacional='{periodo_gestacional}', "
              f"data_envio='{data_envio}', pontuacao_total='{pontuacao_total}', "
              f"classificacao_risco='{classificacao_risco}', imc='{imc}', "
              f"caracteristicas={caracteristicas}")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT nome FROM usuarios WHERE id = ?', (session['user_id'],))
        usuario = cursor.fetchone()
        profissional = usuario['nome'] if usuario else 'Desconhecido'

        required_fields = {
            'Nome da Gestante': nome_gestante,
            'Data de Nascimento': data_nasc,
            'Telefone': telefone,
            'Município': municipio,
            'UBS': ubs,
            'ACS': acs,
            'Período Gestacional': periodo_gestacional,
            'Classificação de Risco': classificacao_risco
        }
        for field_name, field_value in required_fields.items():
            if not field_value or field_value.strip() == '':
                print(f"Erro: Campo obrigatório '{field_name}' está vazio ou ausente: valor='{field_value}'")
                flash(f'O campo "{field_name}" é obrigatório.', 'danger')
                conn.close()
                return redirect(url_for('calculadora'))

        try:
            pontuacao_total = int(pontuacao_total)
        except (ValueError, TypeError):
            print(f"Erro: pontuacao_total inválido: {pontuacao_total}")
            flash('Pontuação total inválida.', 'danger')
            conn.close()
            return redirect(url_for('calculadora'))

        if not re.match(r'^\d{2}/\d{2}/\d{4}$', data_nasc):
            print(f"Erro: Data de nascimento inválida: {data_nasc}")
            flash('Data de nascimento inválida. Use o formato DD/MM/YYYY.', 'danger')
            conn.close()
            return redirect(url_for('calculadora'))

        if not re.match(r'^\d{2}/\d{2}/\d{4}$', data_envio):
            print(f"Erro: Data de envio inválida: {data_envio}")
            flash('Data de envio inválida. Use o formato DD/MM/YYYY.', 'danger')
            conn.close()
            return redirect(url_for('calculadora'))

        caracteristicas_json = json.dumps(caracteristicas)
        avaliacao_nutricional_json = json.dumps(avaliacao_nutricional)
        comorbidades_json = json.dumps(comorbidades)
        historia_obstetrica_json = json.dumps(historia_obstetrica)
        condicoes_gestacionais_json = json.dumps(condicoes_gestacionais)

        codigo_ficha = str(uuid.uuid4())[:8].upper()

        cursor.execute('''
            INSERT INTO calculos (
                user_id, codigo_ficha, nome_gestante, data_nasc, telefone, municipio, ubs, acs,
                periodo_gestacional, data_envio, pontuacao_total, classificacao_risco, imc,
                caracteristicas, avaliacao_nutricional, comorbidades, historia_obstetrica,
                condicoes_gestacionais, profissional
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session['user_id'], codigo_ficha, nome_gestante, data_nasc, telefone, municipio, ubs, acs,
            periodo_gestacional, data_envio, pontuacao_total, classificacao_risco,
            float(imc) if imc else None,
            caracteristicas_json, avaliacao_nutricional_json, comorbidades_json,
            historia_obstetrica_json, condicoes_gestacionais_json, profissional
        ))

        conn.commit()
        print(f"Nova ficha salva: codigo_ficha={codigo_ficha}, nome_gestante='{nome_gestante}', municipio='{municipio}', user_id={session['user_id']}")
        
        cursor.execute('SELECT * FROM calculos WHERE codigo_ficha = ?', (codigo_ficha,))
        ficha_salva = cursor.fetchone()
        if ficha_salva:
            print(f"Confirmação: Ficha encontrada no banco: {dict(ficha_salva)}")
        else:
            print(f"Erro: Ficha com codigo_ficha={codigo_ficha} não encontrada após inserção!")

        conn.close()
        flash(f'Ficha salva com sucesso! Código: {codigo_ficha}', 'success')

        return redirect(url_for('calculadora'))

    except sqlite3.IntegrityError as e:
        print(f"Erro de integridade: {str(e)}")
        flash('Erro: Código da ficha já existe. Tente novamente.', 'danger')
        conn.rollback()
        conn.close()
        return redirect(url_for('calculadora'))
    except sqlite3.OperationalError as e:
        print(f"Erro no banco de dados: {str(e)}")
        flash(f'Erro no banco de dados: {str(e)}', 'danger')
        conn.rollback()
        conn.close()
        return redirect(url_for('calculadora'))
    except Exception as e:
        print(f"Erro ao salvar os dados: {str(e)}")
        flash(f'Erro ao salvar os dados: {str(e)}', 'danger')
        conn.rollback()
        conn.close()
        return redirect(url_for('calculadora'))

@app.route('/historico', methods=['GET'])
def historico():
    if 'user_id' not in session:
        flash('Por favor, faça login para acessar o histórico.', 'danger')
        return redirect(url_for('login'))
    return render_template('historico.html')

@app.route('/buscar_historico', methods=['POST'])
def buscar_historico():
    if 'user_id' not in session:
        return jsonify({'error': 'Por favor, faça login.'}), 401

    data = request.get_json()
    nome_gestante = data.get('nome_gestante', '').strip()
    municipio = data.get('municipio', '').strip()

    print(f"Dados recebidos no backend: nome_gestante='{nome_gestante}', municipio='{municipio}'")

    if not nome_gestante or not municipio:
        return jsonify({'error': 'Nome da gestante e município são obrigatórios'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = '''
            SELECT data_envio, nome_gestante, codigo_ficha, periodo_gestacional,
                   pontuacao_total, classificacao_risco, municipio, ubs, acs,
                   profissional, data_nasc, telefone
            FROM calculos
            WHERE nome_gestante LIKE ? AND municipio LIKE ? AND user_id = ?
            ORDER BY data_envio DESC
        '''
        params = [f'%{nome_gestante}%', f'%{municipio}%', session['user_id']]
        
        cursor.execute(query, params)
        fichas = cursor.fetchall()
        print(f"Busca no histórico: nome_gestante={nome_gestante}, municipio={municipio}, user_id={session['user_id']}, resultados={len(fichas)}")
        for ficha in fichas:
            print(f"Ficha encontrada: {dict(ficha)}")
        conn.close()

        fichas_list = [
            {
                'data_envio': ficha['data_envio'],
                'nome_gestante': ficha['nome_gestante'],
                'codigo_ficha': ficha['codigo_ficha'],
                'periodo_gestacional': ficha['periodo_gestacional'],
                'pontuacao_total': ficha['pontuacao_total'],
                'classificacao_risco': ficha['classificacao_risco'],
                'municipio': ficha['municipio'],
                'ubs': ficha['ubs'],
                'acs': ficha['acs'],
                'profissional': ficha['profissional'],
                'data_nasc': ficha['data_nasc'],
                'telefone': ficha['telefone']
            }
            for ficha in fichas
        ]

        return jsonify({'fichas': fichas_list})

    except Exception as e:
        print(f"Erro ao buscar histórico: {e}")
        return jsonify({'error': 'Erro ao buscar o histórico. Tente novamente.'}), 500

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('Você saiu do sistema.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)