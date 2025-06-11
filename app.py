from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
import sqlite3
import json
import re
import uuid
from datetime import datetime
import bcrypt
from init_db import criar_banco
from functools import wraps
import os
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from PIL import Image as ImageReader
from reportlab.platypus import Image
import logging

# Configuração do logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# Criar o banco de dados
criar_banco()

# Registrar a fonte personalizada para o PDF
try:
    pdfmetrics.registerFont(TTFont('Poppins', 'static/fonts/Poppins-Regular.ttf'))
    pdfmetrics.registerFont(TTFont('Poppins-Bold', 'static/fonts/Poppins-Bold.ttf'))
except Exception as e:
    logging.error(f"Erro ao registrar fontes Poppins: {str(e)}")

# Mapeamentos de chaves internas para rótulos
CARACTERISTICAS_MAP = {
    '15anos': '≤ 15 anos',
    '40anos': '≥ 40 anos',
    'nao_aceita_gravidez': 'Não aceitação da gravidez',
    'violencia_domestica': 'Indícios de Violência Doméstica',
    'rua_indigena_quilombola': 'Situação de rua / indígena ou quilombola',
    'sem_escolaridade': 'Sem escolaridade',
    'tabagista_ativo': 'Tabagista ativo',
    'raca_negra': 'Raça negra'
}

AVALIACAO_NUTRICIONAL_MAP = {
    'baixo_peso': 'Baixo Peso (IMC < 18.5)',
    'sobrepeso': 'Sobrepeso (IMC 25-29.9)',
    'obesidade1': 'Obesidade Grau I (IMC 30-39.9)',
    'obesidade_morbida': 'Obesidade Grau II ou III (IMC ≥ 40)'
}

COMORBIDADES_MAP = {
    'aids_hiv': 'AIDS/HIV',
    'alteracoes_tireoide': 'Alterações da tireoide (hipotireoidismo sem controle e hipertireoidismo)',
    'diabetes_mellitus': 'Diabetes Mellitus',
    'endocrinopatias': 'Endocrinopatias sem controle',
    'cardiopatia': 'Cardiopatia diagnosticada',
    'cancer': 'Câncer Diagnosticado',
    'cirurgia_bariatrica': 'Cirurgia Bariátrica há menos de 1 ano',
    'doencas_autoimunes': 'Doenças Autoimunes (colagenoses)',
    'doencas_psiquiatricas': 'Doenças Psiquiátricas (Encaminhar ao CAPS)',
    'doenca_renal': 'Doença Renal Grave',
    'dependencia_drogas': 'Dependência de Drogas (Encaminhar ao CAPS)',
    'epilepsia': 'Epilepsia e doenças neurológicas graves de difícil controle',
    'hepatites': 'Hepatites (encaminhar ao infectologista)',
    'has_controlada': 'HAS crônica controlada (Sem hipotensor e exames normais)',
    'has_complicada': 'HAS crônica complicada',
    'ginecopatia': 'Ginecopatia (Miomatose ≥ 7cm, malformação uterina, massa anexial ≥ 8cm ou com características complexas)',
    'pneumopatia': 'Pneumopatia grave de difícil controle',
    'tuberculose': 'Tuberculose em tratamento ou com diagnóstico na gestação (Encaminhar ao Pneumologista)',
    'trombofilia': 'Trombofilia ou Tromboembolia',
    'teratogenico': 'Uso de medicações com potencial efeito teratogênico',
    'varizes': 'Varizes acentuadas',
    'doencas_hematologicas': 'Doenças hematológicas (PTI, Anemia Falciforme, PTT, Coagulopatias, Talassemias)',
    'transplantada': 'Transplantada em uso de imunossupressor'
}

HISTORIA_OBSTETRICA_MAP = {
    'abortamentos': '2 abortamentos espontâneos consecutivos ou 3 não consecutivos (confirmados clínico/laboratorial)',
    'abortamentos_consecutivos': '3 ou mais abortamentos espontâneos consecutivos',
    'prematuros': 'Mais de um Prematuro com menos de 36 semanas',
    'obito_fetal': 'Óbito Fetal sem causa determinada',
    'preeclampsia': 'Pré-eclâmpsia ou Pré-eclâmpsia superposta',
    'eclampsia': 'Eclâmpsia',
    'hipertensao_gestacional': 'Hipertensão Gestacional',
    'acretismo': 'Acretismo placentário',
    'descolamento_placenta': 'Descolamento prematuro de placenta',
    'insuficiencia_istmo': 'Insuficiência Istmo Cervical',
    'restricao_crescimento': 'Restrição de Crescimento Intrauterino',
    'malformacao_fetal': 'História de malformação Fetal complexa',
    'isoimunizacao': 'Isoimunização em gestação anterior',
    'diabetes_gestacional': 'Diabetes gestacional',
    'psicose_puerperal': 'Psicose Puerperal',
    'tromboembolia': 'História de tromboembolia'
}

CONDICOES_GESTACIONAIS_MAP = {
    'ameaca_aborto': 'Ameaça de aborto - Encaminhar URGÊNCIA',
    'acretismo_placentario_atual': 'Acretismo Placentário',
    'placenta_previa': 'Placenta Pós',
    'anemia_grave': 'Anemia não responsiva à tratamento (Hb≤8) e hemopatia',
    'citologia_anormal': 'Citologia Cervical anormal (LIEAG) – Encaminhar para PTGI',
    'tireoide_gestacao': 'Doenças da tireoide diagnosticada na gestação',
    'diabetes_gestacional_atual': 'Diabetes gestacional',
    'doenca_hipertensiva': 'Doença Hipertensiva na Gestação (Pré-eclâmpsia, Hipertensão gestacional e Pré-eclâmpsia superada)',
    'doppler_anormal': 'Alteração no doppler das Artérias uterinas (aumento da resistência) e/ou alto risco para Pré-eclâmpsia',
    'doenca_hemolitica': 'Doença Hemolítica',
    'gemelar': 'Gemelar',
    'isoimunizacao_rh': 'Isoimunizacao Rh',
    'insuficiencia_istmo_atual': 'Insuficiência Istmo cervical',
    'colo_curto': 'Colo curto no morfológico 2T',
    'malformacao_congenita': 'Malformação Congênita Fetal',
    'neoplasia_cancer': 'Neoplasia ginecológica ou Câncer diagnosticado na gestação',
    'polidramnio_oligodramnio': 'Polidrâmnio/Oligodrâmnio',
    'restricao_crescimento': 'Restrição de crescimento fetal Intrauterino',
    'toxoplasmose': 'Toxoplasmose',
    'sifilis_complicada': 'Sífilis terciária, Alterações ultrassom sugestivas de sífilis neonatal ou resistência ao tratamento com Penicilina Benzatina',
    'infeccao_urinaria_repeticao': 'Infecção Urinária de repetição (pielonefrite ou ITU≥3x)',
    'hiv_htlv_hepatites': 'HIV, HTLV ou Hepatites Agudas',
    'condilomacao_acuminado': 'Condiloma acuminado (no canal vaginal/colo ou lesões extensas em região genital/perianal)',
    'feto_percentil': 'Feto com percentil > P90 (GIG) ou entre P3-10 (PIG), com doppler normal',
    'hepatopatias': 'Hepatopatias (colestase ou aumento das transaminases)',
    'hanseníase': 'Hanseníase diagnosticada na gestação',
    'tuberculose_gestacao': 'Tuberculose diagnosticada na gestação',
    'dependencia_drogas_atual': 'Dependência e/ou uso abusivo de drogas lícitas e ilícitas'
}

DESFECHO_MAP = {
    'A96': 'Morte',
    'W82': 'Aborto espontâneo',
    'W83': 'Aborto provocado',
    'W90': 'Parto sem complicações de nascido vivo',
    'W91': 'Parto sem complicações de natimorto',
    'W92': 'Parto com complicações de nascido vivo',
    'W93': 'Parto com complicações de natimorto',
    '': 'Não informado',
    None: 'Não informado'
}

def get_db_connection():
    conn = sqlite3.connect('banco.db')
    conn.row_factory = sqlite3.Row
    return conn

def draw_wrapped_text(canvas, text, x, y, max_width, font='Helvetica', font_size=9):
    if not text or not isinstance(text, str) or not text.strip():
        text = "Não informado"
    
    try:
        canvas.setFont(font, font_size)
        logging.debug(f"Fonte definida: {font}, tamanho: {font_size} para texto: {text[:50]}...")
    except Exception as e:
        logging.error(f"Erro ao configurar fonte {font}: {str(e)}. Usando Helvetica como padrão.")
        canvas.setFont('Helvetica', font_size)

    lines = []
    current_line = []
    words = text.split()
    
    for word in words:
        current_line.append(word)
        test_line = ' '.join(current_line)
        if canvas.stringWidth(test_line, font, font_size) > max_width:
            current_line.pop()
            lines.append(' '.join(current_line))
            current_line = [word]
    if current_line:
        lines.append(' '.join(current_line))
    
    if not lines:
        lines.append('Não informado')
    
    line_spacing = 14
    for i, line in enumerate(lines):
        canvas.drawString(x, y - i * line_spacing, line)
    
    total_lines = len(lines)
    total_text_height = total_lines * line_spacing
    new_y = y - total_text_height - 28.35
    
    return new_y

def map_item(campo, item):
    if not item or not isinstance(item, str):
        logging.warning(f"Item inválido para {campo}: {item}")
        return "Item Não Informado"

    item = item.strip()
    mapping = {
        'caracteristicas': CARACTERISTICAS_MAP,
        'avaliacao_nutricional': AVALIACAO_NUTRICIONAL_MAP,
        'comorbidades': COMORBIDADES_MAP,
        'historia_obstetrica': HISTORIA_OBSTETRICA_MAP,
        'condicoes_gestacionais': CONDICOES_GESTACIONAIS_MAP
    }.get(campo, {})
    mapped_item = mapping.get(item, item)
    if mapped_item == item:
        logging.debug(f"Item não mapeado para {campo}: {item}")
    return mapped_item

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para acessar esta página.', 'error')
            return redirect(url_for('login'))
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT is_admin, role, is_super_admin FROM usuarios WHERE id = ?', (session['user_id'],))
            user = cursor.fetchone()
            conn.close()
            if not user or not user['is_admin']:
                flash('Acesso negado. Apenas administradores podem acessar esta página.', 'error')
                return redirect(url_for('calculadora'))
            session['is_admin'] = user['is_admin']
            session['is_super_admin'] = user['is_super_admin']
            session['role'] = user['role']
            return f(*args, **kwargs)
        except sqlite3.OperationalError as e:
            flash(f'Erro no banco de dados: {str(e)}. Contate o administrador do banco de dados.', 'danger')
            return redirect(url_for('calculadora'))
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('password')

        if not email or not senha:
            flash('E-mail e senha são obrigatórios.', 'error')
            return redirect(url_for('login'))

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
            usuario = cursor.fetchone()
            conn.close()

            if usuario and bcrypt.checkpw(senha.encode('utf-8'), usuario['senha'].encode('utf-8')):
                if usuario['approved'] == 0:
                    flash('Sua conta ainda não foi aprovada pelo administrador.', 'error')
                    return redirect(url_for('login'))
                if usuario['ativo'] == 0:
                    flash('Sua conta está inativa. Contate o administrador.', 'error')
                    return redirect(url_for('login'))

                session['user_id'] = usuario['id']
                session['is_admin'] = usuario['is_admin']
                session['role'] = usuario['role']  # Adicionar role à sessão
                flash('Login realizado com sucesso!', 'success')
                if usuario['is_admin']:
                    return redirect(url_for('admin_painel'))
                else:
                    return redirect(url_for('calculadora'))
            else:
                flash('E-mail ou senha incorretos.', 'error')
                return redirect(url_for('login'))
        except sqlite3.OperationalError as e:
            flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Erro ao fazer login: {str(e)}', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nome = request.form.get('nome')
        cpf = request.form.get('cpf')
        profissao = request.form.get('profissao')
        telefone = request.form.get('telefone')
        email = request.form.get('email')
        municipio = request.form.get('municipio')
        cnes = request.form.get('cnes')
        senha = request.form.get('senha')
        confirmar_senha = request.form.get('confirmar')

        if not all([nome, cpf, profissao, telefone, email, municipio, cnes, senha, confirmar_senha]):
            flash('Todos os campos são obrigatórios.', 'error')
            return redirect(url_for('register'))

        if senha != confirmar_senha:
            flash('As senhas não coincidem.', 'error')
            return redirect(url_for('register'))
        
        if len(senha) < 6:
            flash('A senha deve ter pelo menos 6 caracteres.', 'error')
            return redirect(url_for('register'))

        cpf = re.sub(r'[^\d]', '', cpf)
        if not re.match(r'^\d{11}$', cpf):
            flash('CPF inválido. Deve conter exatamente 11 dígitos (com ou sem formatação).', 'error')
            return redirect(url_for('register'))

        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            flash('E-mail inválido.', 'error')
            return redirect(url_for('register'))

        senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO usuarios (nome, cpf, profissao, telefone, email, municipio, cnes, senha, is_admin, approved, ativo, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (nome, cpf, profissao, telefone, email, municipio, cnes, senha_hash, 0, 0, 0, 'municipal'))
            conn.commit()
            conn.close()
            flash('Cadastro realizado com sucesso! Aguarde aprovação.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('E-mail ou CPF já cadastrado.', 'error')
            return redirect(url_for('register'))
        except sqlite3.OperationalError as e:
            flash(f'Erro no banco de dados: {str(e)}. Contate o administrador do banco de dados.', 'danger')
            return redirect(url_for('register'))
        except Exception as e:
            flash(f'Erro ao cadastrar: {str(e)}', 'error')
            return redirect(url_for('register'))

    return render_template('login.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('As novas senhas não coincidem.', 'error')
            return redirect(url_for('login'))

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(old_password.encode('utf-8'), user['senha'].encode('utf-8')):
                new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cursor.execute('UPDATE usuarios SET senha = ? WHERE email = ?', (new_password_hash, email))
                conn.commit()
                flash('Senha redefinida com sucesso! Faça login.', 'success')
            else:
                flash('E-mail ou senha atual inválidos.', 'error')

            conn.close()
            return redirect(url_for('login'))
        except sqlite3.OperationalError as e:
            flash(f'Erro no banco de dados: {str(e)}. Contate o administrador do banco de dados.', 'danger')
            return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/calculadora', methods=['GET'])
def calculadora():
    if 'user_id' not in session:
        flash('Por favor, faça login para acessar a calculadora.', 'error')
        return redirect(url_for('login'))

    ficha = None
    codigo_ficha = request.args.get('codigo_ficha')
    if codigo_ficha:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM calculos WHERE codigo_ficha = ? AND user_id = ?', (codigo_ficha, session['user_id']))
            ficha = cursor.fetchone()
            if ficha:
                ficha = dict(ficha)
                for field in ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 'historia_obstetrica', 'condicoes_gestacionais']:
                    if ficha[field] and isinstance(ficha[field], str):
                        try:
                            ficha[field] = json.loads(ficha[field])
                            if not isinstance(ficha[field], list):
                                ficha[field] = [ficha[field]] if ficha[field] else []
                        except json.JSONDecodeError:
                            ficha[field] = [ficha[field]] if ficha[field] else []
                    else:
                        ficha[field] = []
            conn.close()
        except sqlite3.OperationalError as e:
            flash(f'Erro no banco de dados: {str(e)}. Contate o administrador do banco de dados.', 'danger')
            ficha = None
        except Exception as e:
            logging.error(f"Erro ao carregar ficha {codigo_ficha}: {str(e)}")
            flash('Erro ao carregar a ficha.', 'error')
            ficha = None

    return render_template('calculadora.html', ficha=ficha)

@app.route('/salvar_calculadora', methods=['POST'])
def salvar_calculadora():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Por favor, faça login para salvar os dados.'}), 401

    try:
        logging.debug(f"Dados recebidos do formulário: {request.form}")

        nome_gestante = request.form.get('nome_gestante')
        data_nasc = request.form.get('data_nasc')
        telefone = request.form.get('telefone')
        municipio = request.form.get('municipio')
        ubs = request.form.get('ubs')
        acs = request.form.get('acs')
        periodo_gestacional = request.form.get('periodo_gestacional')
        data_envio = request.form.get('data_envio', datetime.now().strftime('%d/%m/%Y'))
        pontuacao_total = request.form.get('pontuacao_total')
        classificacao_risco = request.form.get('classificacao_risco', 'Risco Habitual')
        imc = request.form.get('imc', None)

        def parse_json_field(field_name):
            field_value = request.form.get(field_name, '[]')
            try:
                parsed = json.loads(field_value)
                if not isinstance(parsed, list):
                    parsed = [parsed] if parsed else []
                return [str(item) for item in parsed if item and str(item).strip()]
            except json.JSONDecodeError as e:
                logging.warning(f"Erro ao desserializar {field_name}: {str(e)} - Valor bruto: {field_value}")
                return []

        caracteristicas = parse_json_field('caracteristicas')
        avaliacao_nutricional = parse_json_field('avaliacao_nutricional')
        comorbidades = parse_json_field('comorbidades')
        historia_obstetrica = parse_json_field('historia_obstetrica')
        condicoes_gestacionais = parse_json_field('condicoes_gestacionais')

        logging.debug(f"Características: {caracteristicas}")
        logging.debug(f"Avaliação Nutricional: {avaliacao_nutricional}")
        logging.debug(f"Comorbidades: {comorbidades}")
        logging.debug(f"História Obstétrica: {historia_obstetrica}")
        logging.debug(f"Condições Gestacionais: {condicoes_gestacionais}")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT nome FROM usuarios WHERE id = ?', (session['user_id'],))
        usuario = cursor.fetchone()
        if not usuario:
            conn.close()
            return jsonify({'success': False, 'message': 'Usuário não encontrado.'}), 400
        profissional = usuario['nome']

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
                conn.close()
                return jsonify({
                    'success': False,
                    'message': f'O campo "{field_name}" é obrigatório.'
                }), 400

        try:
            pontuacao_total = int(pontuacao_total) if pontuacao_total and pontuacao_total.strip() else 0
        except (ValueError, TypeError):
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Pontuação total inválida.'
            }), 400

        if not re.match(r'^\d{2}/\d{2}/\d{4}$', data_nasc):
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Data de nascimento inválida. Use o formato DD/MM/YYYY.'
            }), 400

        if not re.match(r'^\d{2}/\d{2}/\d{4}$', data_envio):
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Data de envio inválida. Use o formato DD/MM/YYYY.'
            }), 400

        caracteristicas_json = json.dumps(caracteristicas)
        avaliacao_nutricional_json = json.dumps(avaliacao_nutricional)
        comorbidades_json = json.dumps(comorbidades)
        historia_obstetrica_json = json.dumps(historia_obstetrica)
        condicoes_gestacionais_json = json.dumps(condicoes_gestacionais)

        logging.debug(f"JSON salvo - Características: {caracteristicas_json}")
        logging.debug(f"JSON salvo - Avaliação Nutricional: {avaliacao_nutricional_json}")
        logging.debug(f"JSON salvo - Comorbidades: {comorbidades_json}")
        logging.debug(f"JSON salvo - História Obstétrica: {historia_obstetrica_json}")
        logging.debug(f"JSON salvo - Condições Gestacionais: {condicoes_gestacionais_json}")

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
            float(imc) if imc and imc.strip() else None,
            caracteristicas_json, avaliacao_nutricional_json, comorbidades_json,
            historia_obstetrica_json, condicoes_gestacionais_json, profissional
        ))

        conn.commit()
        cursor.execute('SELECT * FROM calculos WHERE codigo_ficha = ?', (codigo_ficha,))
        ficha_salva = cursor.fetchone()
        conn.close()

        if not ficha_salva:
            return jsonify({
                'success': False,
                'message': 'Erro ao salvar a ficha no banco de dados.'
            }), 500

        return jsonify({
            'success': True,
            'codigo_ficha': codigo_ficha,
            'message': f'Ficha salva com sucesso! Código: {codigo_ficha}',
            'dados': {
                'nome_gestante': nome_gestante,
                'data_nasc': data_nasc,
                'telefone': telefone,
                'municipio': municipio,
                'ubs': ubs,
                'acs': acs,
                'periodo_gestacional': periodo_gestacional,
                'data_envio': data_envio,
                'pontuacao_total': pontuacao_total,
                'classificacao_risco': classificacao_risco,
                'imc': imc,
                'caracteristicas': caracteristicas,
                'avaliacao_nutricional': avaliacao_nutricional,
                'comorbidades': comorbidades,
                'historia_obstetrica': historia_obstetrica,
                'condicoes_gestacionais': condicoes_gestacionais,
                'profissional': profissional
            }
        })

    except sqlite3.IntegrityError as e:
        conn.rollback()
        conn.close()
        logging.error(f"Erro de integridade: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erro de integridade no banco de dados: {str(e)}'
        }), 500
    except sqlite3.OperationalError as e:
        conn.rollback()
        conn.close()
        logging.error(f"Erro operacional no banco: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erro no banco de dados: {str(e)}'
        }), 500
    except Exception as e:
        conn.rollback()
        conn.close()
        logging.error(f"Erro geral ao salvar: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erro ao salvar os dados: {str(e)}'
        }), 500

@app.route('/historico', methods=['GET'])
def historico():
    if 'user_id' not in session:
        flash('Por favor, faça login para acessar o histórico.', 'error')
        return redirect(url_for('login'))

    return render_template('historico.html')

@app.route('/buscar_historico', methods=['POST'])
def buscar_historico():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Por favor, faça login para buscar o histórico.'}), 401

    try:
        data = request.get_json()
        page = data.get('page', 1)
        per_page = data.get('per_page', 100)
        sort_column = data.get('sort_column', 'data_envio')
        sort_direction = data.get('sort_direction', 'DESC')

        if not isinstance(page, int) or page < 1:
            page = 1
        if not isinstance(per_page, int) or per_page < 1 or per_page > 200:
            per_page = 100
        sort_column = sort_column.lower() if sort_column else 'data_envio'
        sort_direction = sort_direction.upper() if sort_direction in ['ASC', 'DESC'] else 'DESC'

        valid_columns = [
            'data_envio', 'nome_gestante', 'codigo_ficha', 'periodo_gestacional',
            'pontuacao_total', 'classificacao_risco', 'municipio', 'ubs', 'acs', 'profissional'
        ]
        if sort_column not in valid_columns:
            sort_column = 'data_envio'

        conn = get_db_connection()
        cursor = conn.cursor()

        query_count = '''
            SELECT COUNT(*) as total
            FROM calculos 
            WHERE user_id = ? AND (desfecho IS NULL OR desfecho = '')
        '''
        cursor.execute(query_count, (session['user_id'],))
        total_records = cursor.fetchone()['total']

        offset = (page - 1) * per_page
        query = f'''
            SELECT codigo_ficha, nome_gestante, data_envio, periodo_gestacional, 
                   pontuacao_total, classificacao_risco, municipio, ubs, acs, profissional
            FROM calculos 
            WHERE user_id = ? AND (desfecho IS NULL OR desfecho = '')
            ORDER BY {sort_column} {sort_direction}
            LIMIT ? OFFSET ?
        '''
        cursor.execute(query, (session['user_id'], per_page, offset))
        fichas = cursor.fetchall()
        conn.close()

        fichas_list = [dict(ficha) for ficha in fichas]

        return jsonify({
            'success': True,
            'fichas': fichas_list,
            'total_records': total_records,
            'message': f'{len(fichas_list)} registro(s) encontrado(s).'
        })

    except sqlite3.OperationalError as e:
        logging.error(f"Erro no banco de dados: {str(e)}")
        return jsonify({'success': False, 'message': f'Erro no banco de dados: {str(e)}'}), 500
    except Exception as e:
        logging.error(f"Erro ao buscar histórico: {str(e)}")
        return jsonify({'success': False, 'message': f'Erro ao buscar o histórico: {str(e)}'}), 500

@app.route('/registrar_desfecho', methods=['POST'])
def registrar_desfecho():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Por favor, faça login para registrar o desfecho.'}), 401

    try:
        data = request.get_json()
        codigo_ficha = data.get('codigo_ficha')
        desfecho = data.get('desfecho')

        if not codigo_ficha or not desfecho:
            return jsonify({
                'success': False,
                'message': 'Código da ficha e desfecho são obrigatórios.'
            }), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM calculos WHERE codigo_ficha = ? AND user_id = ?', (codigo_ficha, session['user_id']))
        ficha = cursor.fetchone()

        if not ficha:
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Ficha não encontrada ou você não tem acesso a ela.'
            }), 404

        data_desfecho = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        cursor.execute('UPDATE calculos SET desfecho = ?, data_desfecho = ? WHERE codigo_ficha = ?', 
                       (desfecho, data_desfecho, codigo_ficha))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Desfecho registrado com sucesso!'
        })

    except sqlite3.OperationalError as e:
        conn.rollback()
        conn.close()
        logging.error(f"Erro no banco de dados: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erro no banco de dados: {str(e)}'
        }), 500
    except Exception as e:
        conn.rollback()
        conn.close()
        logging.error(f"Erro ao registrar desfecho: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erro ao registrar desfecho: {str(e)}'
        }), 500

@app.route('/obter_ficha_completa', methods=['POST'])
def obter_ficha_completa():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Por favor, faça login para acessar a ficha.'}), 401

    try:
        data = request.get_json()
        codigo_ficha = data.get('code')

        if not codigo_ficha:
            return jsonify({'error': 'Código da ficha não fornecido.'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM calculos 
            WHERE codigo_ficha = ? AND user_id = ?
        ''', (codigo_ficha, session['user_id']))
        ficha = cursor.fetchone()
        conn.close()

        if not ficha:
            return jsonify({'error': 'Ficha não encontrada ou você não tem acesso a ela.'}), 404

        ficha_dict = dict(ficha)

        logging.debug(f"Valores brutos para ficha {codigo_ficha}:")
        for field in ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 'historia_obstetrica', 'condicoes_gestacionais']:
            logging.debug(f"{field} (raw): {ficha_dict[field]}")

        try:
            for field in ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 'historia_obstetrica', 'condicoes_gestacionais']:
                raw_value = ficha_dict[field]
                if raw_value is None or raw_value == '':
                    ficha_dict[field] = []
                else:
                    try:
                        parsed_value = json.loads(raw_value)
                        if not isinstance(parsed_value, list):
                            parsed_value = [parsed_value] if parsed_value else []
                        if parsed_value and isinstance(parsed_value, list) and len(parsed_value) == 1:
                            try:
                                nested_items = json.loads(parsed_value[0]) if isinstance(parsed_value[0], str) else parsed_value[0]
                                if isinstance(nested_items, list):
                                    parsed_value = nested_items
                                elif nested_items:
                                    parsed_value = [nested_items]
                            except json.JSONDecodeError:
                                pass
                        ficha_dict[field] = parsed_value
                    except json.JSONDecodeError as e:
                        logging.warning(f"Erro ao desserializar {field}: {str(e)} - Valor bruto: {raw_value}")
                        ficha_dict[field] = [raw_value] if raw_value else []
        except Exception as e:
            logging.error(f"Erro geral ao desserializar JSON: {str(e)}")
            return jsonify({'error': 'Erro ao processar dados da ficha.'}), 500

        logging.debug(f"Valores após desserialização para ficha {codigo_ficha}:")
        for field in ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 'historia_obstetrica', 'condicoes_gestacionais']:
            logging.debug(f"{field} (parsed): {ficha_dict[field]}")

        # Mapear os itens para exibição
        mapped_data = {}
        for field in ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 'historia_obstetrica', 'condicoes_gestacionais']:
            mapped_data[field] = [map_item(field, item) for item in ficha_dict[field] if item]

        logging.debug(f"Valores após mapeamento para ficha {codigo_ficha}:")
        for field in ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 'historia_obstetrica', 'condicoes_gestacionais']:
            logging.debug(f"{field} (mapped): {mapped_data[field]}")

        return jsonify({'ficha': ficha_dict, 'mapped_data': mapped_data}), 200

    except sqlite3.OperationalError as e:
        logging.error(f"Erro no banco de dados: {str(e)}")
        return jsonify({'error': f'Erro no banco de dados: {str(e)}'}), 500
    except Exception as e:
        logging.error(f"Erro ao buscar ficha: {str(e)}")
        return jsonify({'error': f'Erro ao buscar ficha: {str(e)}'}), 500

@app.route('/logout', methods=['POST'])
def logout():
    if 'user_id' in session:
        session.pop('user_id', None)
        session.pop('is_admin', None)
        session.pop('role', None)
        return jsonify({'success': True, 'message': 'Logout realizado com sucesso.'})
    return jsonify({'success': False, 'message': 'Nenhuma sessão ativa.'}), 401

@app.route('/admin/painel', methods=['GET'])
@admin_required
def admin_painel():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id, nome, email, municipio, profissao, cnes FROM usuarios WHERE approved = 0')
        usuarios_pendentes = [dict(user) for user in cursor.fetchall()]

        cursor.execute('SELECT id, nome, email, municipio, profissao, cnes, ativo FROM usuarios WHERE approved = 1')
        usuarios_cadastrados = [dict(user) for user in cursor.fetchall()]

        page = request.args.get('page', 1, type=int)
        per_page = 100
        offset = (page - 1) * per_page

        cursor.execute('SELECT COUNT(*) AS total FROM acoes_administrativas')
        result = cursor.fetchone()
        total_acoes = result['total'] if result else 0

        total_pages = (total_acoes + per_page - 1) // per_page

        cursor.execute('''
            SELECT a.data_acao, u1.nome AS admin_nome, u2.nome AS usuario_nome, a.acao, a.detalhes
            FROM acoes_administrativas a
            LEFT JOIN usuarios u1 ON a.admin_id = u1.id
            LEFT JOIN usuarios u2 ON a.usuario_id = u2.id
            ORDER BY a.data_acao DESC
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        historico_acoes = [dict(acao) for acao in cursor.fetchall()]

        class Pagination:
            def __init__(self, items, page, per_page, total, total_pages):
                self.items = items
                self.page = page
                self.per_page = per_page
                self.total = total
                self.pages = total_pages
                self.has_prev = page > 1
                self.has_next = page < total_pages
                self.prev_num = page - 1 if self.has_prev else None
                self.next_num = page + 1 if self.has_next else None

        paginated_historico = Pagination(historico_acoes, page, per_page, total_acoes, total_pages)

        conn.close()
        return render_template('admin_painel.html', 
                             usuarios_pendentes=usuarios_pendentes,
                             usuarios_cadastrados=usuarios_cadastrados,
                             historico_acoes=paginated_historico)
    except sqlite3.OperationalError as e:
        if conn:
            conn.close()
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
        return redirect(url_for('calculadora'))
    except Exception as e:
        if conn:
            conn.close()
        flash(f'Erro ao carregar painel administrativo: {str(e)}.', 'danger')
        return redirect(url_for('calculadora'))

@app.route('/admin/aprovar_usuario', methods=['POST'])
@admin_required
def admin_aprovar_usuario():
    usuario_id = request.form.get('usuario_id')
    if not usuario_id:
        flash('ID do usuário inválido.', 'danger')
        return redirect(url_for('admin_painel'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET approved = 1, ativo = 1 WHERE id = ?', (usuario_id,))
        if cursor.rowcount == 0:
            flash('Usuário não encontrado.', 'danger')
        else:
            cursor.execute('''
                INSERT INTO acoes_administrativas (admin_id, usuario_id, acao, data_acao, detalhes)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['user_id'], usuario_id, 'Aprovação', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                  f'Usuário ID {usuario_id} aprovado'))
            conn.commit()
            flash('Usuário aprovado com sucesso.', 'success')
        conn.close()
    except sqlite3.OperationalError as e:
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
    return redirect(url_for('admin_painel'))

@app.route('/admin/rejeitar_usuario', methods=['POST'])
@admin_required
def admin_rejeitar_usuario():
    usuario_id = request.form.get('usuario_id')
    if not usuario_id:
        flash('ID do usuário inválido.', 'danger')
        return redirect(url_for('admin_painel'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM usuarios WHERE id = ?', (usuario_id,))
        if cursor.rowcount == 0:
            flash('Usuário não encontrado.', 'danger')
        else:
            cursor.execute('''
                INSERT INTO acoes_administrativas (admin_id, usuario_id, acao, data_acao, detalhes)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['user_id'], usuario_id, 'Rejeição', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                  f'Usuário ID {usuario_id} rejeitado e removido'))
            conn.commit()
            flash('Usuário rejeitado e removido.', 'success')
        conn.close()
    except sqlite3.OperationalError as e:
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
    return redirect(url_for('admin_painel'))

@app.route('/admin/ativar_usuario', methods=['POST'])
@admin_required
def admin_ativar_usuario():
    usuario_id = request.form.get('usuario_id')
    if not usuario_id:
        flash('ID do usuário inválido.', 'danger')
        return redirect(url_for('admin_painel'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET ativo = 1 WHERE id = ?', (usuario_id,))
        if cursor.rowcount == 0:
            flash('Usuário não encontrado.', 'danger')
        else:
            cursor.execute('''
                INSERT INTO acoes_administrativas (admin_id, usuario_id, acao, data_acao, detalhes)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['user_id'], usuario_id, 'Ativação', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                  f'Usuário ID {usuario_id} ativado'))
            conn.commit()
            flash('Usuário ativado com sucesso.', 'success')
        conn.close()
    except sqlite3.OperationalError as e:
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
    return redirect(url_for('admin_painel'))

@app.route('/admin/desativar_usuario', methods=['POST'])
@admin_required
def admin_desativar_usuario():
    usuario_id = request.form.get('usuario_id')
    if not usuario_id:
        flash('ID do usuário inválido.', 'danger')
        return redirect(url_for('admin_painel'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET ativo = 0 WHERE id = ?', (usuario_id,))
        if cursor.rowcount == 0:
            flash('Usuário não encontrado.', 'danger')
        else:
            cursor.execute('''
                INSERT INTO acoes_administrativas (admin_id, usuario_id, acao, data_acao, detalhes)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['user_id'], usuario_id, 'Desativação', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                  f'Usuário ID {usuario_id} desativado'))
            conn.commit()
            flash('Usuário desativado com sucesso.', 'success')
        conn.close()
    except sqlite3.OperationalError as e:
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
    return redirect(url_for('admin_painel'))

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para acessar esta página.', 'error')
            return redirect(url_for('login'))
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT is_admin, role, is_super_admin FROM usuarios WHERE id = ?', (session['user_id'],))
            user = cursor.fetchone()
            conn.close()
            if not user or user['role'] != 'estadual' or not user['is_super_admin']:
                flash('Acesso negado: apenas administradores estaduais podem acessar esta página.', 'error')
                return redirect(url_for('admin_painel'))
            return f(*args, **kwargs)
        except sqlite3.OperationalError as e:
            flash(f'Erro no banco de dados: {str(e)}. Contate o administrador do banco de dados.', 'danger')
            return redirect(url_for('admin_painel'))
    return decorated_function

@app.route('/admin/gerenciar_usuarios', methods=['GET', 'POST'])
@super_admin_required
def admin_gerenciar_usuarios():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Obter parâmetros de paginação
        page = request.args.get('page', 1, type=int)
        per_page = 100
        offset = (page - 1) * per_page

        # Contar total de usuários ativos
        cursor.execute('SELECT COUNT(*) AS total FROM usuarios WHERE ativo = 1 AND approved = 1')
        total_usuarios = cursor.fetchone()['total']
        total_pages = (total_usuarios + per_page - 1) // per_page

        # Obter usuários ativos com paginação
        cursor.execute('''
            SELECT id, nome, email, municipio, profissao, cnes, role, is_admin, is_super_admin
            FROM usuarios
            WHERE ativo = 1 AND approved = 1
            ORDER BY nome ASC
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        usuarios = [dict(user) for user in cursor.fetchall()]

        # Lidar com a promoção de usuário
        if request.method == 'POST':
            usuario_id = request.form.get('usuario_id')
            novo_role = request.form.get('novo_role')

            if not usuario_id or not novo_role:
                flash('ID do usuário ou novo papel inválido.', 'danger')
                conn.close()
                return redirect(url_for('admin_gerenciar_usuarios', page=page))

            if novo_role not in ['comum', 'municipal', 'estadual']:
                flash('Papel inválido. Escolha entre comum, municipal ou estadual.', 'danger')
                conn.close()
                return redirect(url_for('admin_gerenciar_usuarios', page=page))

            # Verificar se o usuário está tentando modificar a si mesmo
            if int(usuario_id) == session['user_id']:
                flash('Você não pode modificar seu próprio papel.', 'danger')
                conn.close()
                return redirect(url_for('admin_gerenciar_usuarios', page=page))

            # Definir permissões com base no novo_role
            if novo_role == 'comum':
                is_admin = 0
                is_super_admin = 0
            elif novo_role == 'municipal':
                is_admin = 1
                is_super_admin = 0
            elif novo_role == 'estadual':
                is_admin = 1
                is_super_admin = 1

            cursor.execute('''
                UPDATE usuarios
                SET role = ?, is_admin = ?, is_super_admin = ?
                WHERE id = ?
            ''', (novo_role, is_admin, is_super_admin, usuario_id))

            if cursor.rowcount == 0:
                flash('Usuário não encontrado.', 'danger')
            else:
                # Registrar a ação administrativa
                cursor.execute('''
                    INSERT INTO acoes_administrativas (admin_id, usuario_id, acao, data_acao, detalhes)
                    VALUES (?, ?, ?, ?, ?)
                ''', (session['user_id'], usuario_id, 'Alteração de Papel',
                      datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                      f'Usuário ID {usuario_id} alterado para {novo_role}'))
                conn.commit()
                flash(f'Papel do usuário alterado para {novo_role.capitalize()} com sucesso.', 'success')

            conn.close()
            return redirect(url_for('admin_gerenciar_usuarios', page=page))

        # Configurar paginação
        class Pagination:
            def __init__(self, items, page, per_page, total, total_pages):
                self.items = items
                self.page = page
                self.per_page = per_page
                self.total = total
                self.pages = total_pages
                self.has_prev = page > 1
                self.has_next = page < total_pages
                self.prev_num = page - 1 if self.has_prev else None
                self.next_num = page + 1 if self.has_next else None

        paginated_usuarios = Pagination(usuarios, page, per_page, total_usuarios, total_pages)

        conn.close()
        return render_template('admin_gerenciar_usuarios.html',
                             usuarios=paginated_usuarios,
                             current_page=page,
                             total_pages=total_pages)

    except sqlite3.OperationalError as e:
        if conn:
            conn.close()
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
        return redirect(url_for('admin_painel'))
    except Exception as e:
        if conn:
            conn.close()
        flash(f'Erro ao carregar gerenciamento de usuários: {str(e)}.', 'danger')
        return redirect(url_for('admin_painel'))

@app.route('/admin/senha', methods=['GET'])
@admin_required
def admin_senha():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, nome, email, approved FROM usuarios')
        usuarios = [dict(user) for user in cursor.fetchall()]
        conn.close()
        return render_template('admin_senha.html', usuarios=usuarios)
    except sqlite3.OperationalError as e:
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
        return redirect(url_for('calculadora'))

@app.route('/admin/reset_senha', methods=['POST'])
@admin_required
def admin_reset_senha():
    email = request.form.get('email')
    nova_senha = request.form.get('nova_senha')

    if not email or not nova_senha:
        flash('E-mail e nova senha são obrigatórios.', 'error')
        return redirect(url_for('admin_senha'))

    if len(nova_senha) < 6:
        flash('A nova senha deve ter pelo menos 6 caracteres.', 'error')
        return redirect(url_for('admin_senha'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM usuarios WHERE email = ?', (email,))
        user = cursor.fetchone()

        if not user:
            flash('Usuário não encontrado.', 'error')
            conn.close()
            return redirect(url_for('admin_senha'))

        nova_senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('UPDATE usuarios SET senha = ? WHERE email = ?', (nova_senha_hash, email))
        conn.commit()
        conn.close()
        flash('Senha redefinida com sucesso.', 'success')
        return redirect(url_for('admin_senha'))
    except sqlite3.Error as e:
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'error')
        return redirect(url_for('admin_senha'))

@app.route('/admin/relatorio', methods=['GET', 'POST'])
@admin_required
def admin_relatorio():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Obter informações do usuário atual
        cursor.execute('SELECT municipio, role, is_admin, is_super_admin FROM usuarios WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        if not user:
            conn.close()
            flash('Usuário não encontrado.', 'error')
            return redirect(url_for('calculadora'))

        user_municipio = user['municipio']
        user_role = user['role']
        is_admin = user['is_admin']
        is_super_admin = user['is_super_admin']

        # Lista de municípios disponíveis
        if is_super_admin == 1 and user_role == 'estadual':
            cursor.execute('SELECT DISTINCT municipio FROM calculos ORDER BY municipio')
            municipios = [row['municipio'] for row in cursor.fetchall()]
        else:
            municipios = [user_municipio]

        registros = []
        filtro_municipio = None

        if request.method == 'POST':
            filtro_municipio = request.form.get('municipio')
            if is_admin == 1 and user_role == 'municipal' and filtro_municipio != user_municipio:
                flash('Acesso negado. Você só pode visualizar registros do seu município.', 'error')
                return redirect(url_for('admin_relatorio'))

        # Montar a query com base no role e filtro
        query_params = []
        query = '''
            SELECT user_id, codigo_ficha, nome_gestante, data_nasc, telefone, municipio, ubs, acs,
                   periodo_gestacional, data_envio, pontuacao_total, classificacao_risco, imc,
                   caracteristicas, avaliacao_nutricional, comorbidades, historia_obstetrica,
                   condicoes_gestacionais, profissional, desfecho
            FROM calculos
        '''
        if is_admin == 1 and user_role == 'municipal':
            query += ' WHERE municipio = ?'
            query_params.append(user_municipio)
            filtro_municipio = user_municipio
        elif is_super_admin == 1 and user_role == 'estadual' and filtro_municipio:
            query += ' WHERE municipio = ?'
            query_params.append(filtro_municipio)

        query += ' ORDER BY data_envio DESC'
        cursor.execute(query, query_params)
        registros = []

        for row in cursor.fetchall():
            registro = dict(row)
            for field, mapping in [
                ('caracteristicas', CARACTERISTICAS_MAP),
                ('avaliacao_nutricional', AVALIACAO_NUTRICIONAL_MAP),
                ('comorbidades', COMORBIDADES_MAP),
                ('historia_obstetrica', HISTORIA_OBSTETRICA_MAP),
                ('condicoes_gestacionais', CONDICOES_GESTACIONAIS_MAP)
            ]:
                try:
                    if registro[field] and isinstance(registro[field], str) and registro[field].strip():
                        try:
                            items = json.loads(registro[field])
                            if not isinstance(items, list):
                                items = [items] if items else []
                        except json.JSONDecodeError:
                            items = [registro[field].strip()] if registro[field].strip() else []
                    else:
                        items = []
                    mapped_items = [mapping.get(item, item) for item in items if item and item.strip()]
                    registro[field] = ', '.join(mapped_items) if mapped_items else '-'
                except Exception as e:
                    logging.error(f"Erro ao processar {field} para ficha {registro['codigo_ficha']}: {str(e)}")
                    registro[field] = '-'
            if registro['classificacao_risco'] and isinstance(registro['classificacao_risco'], str):
                classificacao = registro['classificacao_risco'].strip().lower()
                if classificacao == 'risco habitual':
                    registro['classificacao_risco'] = 'Risco Habitual'
                elif classificacao == 'médio risco':
                    registro['classificacao_risco'] = 'Risco Intermediário'
                elif classificacao == 'alto risco':
                    registro['classificacao_risco'] = 'Risco Alto'
            registro['desfecho'] = DESFECHO_MAP.get(registro['desfecho'], 'Não informado')
            registros.append(registro)

        from collections import Counter
        caracteristicas_counts = Counter()
        avaliacao_nutricional_counts = Counter()
        comorbidades_counts = Counter()
        historia_obstetrica_counts = Counter()
        condicoes_gestacionais_counts = Counter()
        desfecho_counts = Counter()

        for registro in registros:
            for field, mapping, counter in [
                ('caracteristicas', CARACTERISTICAS_MAP, caracteristicas_counts),
                ('avaliacao_nutricional', AVALIACAO_NUTRICIONAL_MAP, avaliacao_nutricional_counts),
                ('comorbidades', COMORBIDADES_MAP, comorbidades_counts),
                ('historia_obstetrica', HISTORIA_OBSTETRICA_MAP, historia_obstetrica_counts),
                ('condicoes_gestacionais', CONDICOES_GESTACIONAIS_MAP, condicoes_gestacionais_counts)
            ]:
                try:
                    items = []
                    raw_value = registro[field]
                    logging.debug(f"Processando {field} para ficha {registro['codigo_ficha']}: {raw_value} (tipo: {type(raw_value)})")

                    if raw_value and isinstance(raw_value, str) and raw_value.strip() and raw_value != '-':
                        try:
                            items = json.loads(raw_value)
                            if not isinstance(items, list):
                                items = [items] if items else []
                            items = [str(item).strip() for item in items if item and str(item).strip()]
                            logging.debug(f"Itens desserializados para {field}: {items}")
                        except json.JSONDecodeError as e:
                            logging.warning(f"Erro ao desserializar {field} para ficha {registro['codigo_ficha']}: {str(e)} - Valor bruto: {raw_value}")
                            items = [item.strip() for item in raw_value.split(',') if item.strip()]
                            logging.debug(f"Itens após split para {field}: {items}")
                    else:
                        logging.debug(f"Campo {field} vazio ou inválido para ficha {registro['codigo_ficha']}: {raw_value}")

                    for item in items:
                        if item:
                            mapped_item = mapping.get(item, item)
                            if mapped_item and mapped_item != '-':
                                counter[mapped_item] += 1
                                logging.debug(f"Contado {field}: {mapped_item} (contagem: {counter[mapped_item]})")
                except Exception as e:
                    logging.error(f"Erro ao contar {field} para ficha {registro['codigo_ficha']}: {str(e)}")

            # Contar desfecho
            desfecho = registro['desfecho']
            if desfecho:
                desfecho_counts[desfecho] += 1
                logging.debug(f"Contado desfecho: {desfecho} (contagem: {desfecho_counts[desfecho]})")

        for counter in [caracteristicas_counts, avaliacao_nutricional_counts, comorbidades_counts, 
                        historia_obstetrica_counts, condicoes_gestacionais_counts, desfecho_counts]:
            if '-' in counter:
                del counter['-']

        total_registros = len(registros)
        municipios_unicos = len(set(registro['municipio'] for registro in registros))
        
        periodo_gestacional = Counter(registro['periodo_gestacional'] for registro in registros if registro['periodo_gestacional'])
        
        pontuacao_total = [registro['pontuacao_total'] for registro in registros if registro['pontuacao_total'] is not None]
        media_pontuacao = sum(pontuacao_total) / len(pontuacao_total) if pontuacao_total else 0
        
        classificacao_risco = Counter(registro['classificacao_risco'] for registro in registros if registro['classificacao_risco'])

        estatisticas = {
            'total_registros': total_registros,
            'municipios_unicos': municipios_unicos,
            'periodo_gestacional': dict(periodo_gestacional),
            'media_pontuacao': round(media_pontuacao, 1),
            'classificacao_risco': {
                'risco_habitual': classificacao_risco.get('Risco Habitual', 0),
                'risco_intermediario': classificacao_risco.get('Risco Intermediário', 0),
                'risco_alto': classificacao_risco.get('Risco Alto', 0)
            },
            'caracteristicas_counts': dict(caracteristicas_counts),
            'avaliacao_nutricional_counts': dict(avaliacao_nutricional_counts),
            'comorbidades_counts': dict(comorbidades_counts),
            'historia_obstetrica_counts': dict(historia_obstetrica_counts),
            'condicoes_gestacionais_counts': dict(condicoes_gestacionais_counts),
            'desfecho_counts': dict(desfecho_counts)
        }

        conn.close()
        return render_template('admin_relatorio.html', municipios=municipios, registros=registros, 
                             filtro_municipio=filtro_municipio, estatisticas=estatisticas, 
                             is_super_admin=is_super_admin, user_role=user_role)

    except sqlite3.OperationalError as e:
        if conn:
            conn.close()
        flash(f'Erro no banco de dados: {str(e)}.', 'error')
        return redirect(url_for('calculadora'))
    except Exception as e:
        if conn:
            conn.close()
        logging.error(f"Erro ao carregar relatório: {str(e)}")
        flash(f'Erro ao carregar relatório: {str(e)}.', 'error')
        return redirect(url_for('calculadora'))

@app.route('/gerar_pdf/<code>')
def gerar_pdf(code):
    if 'user_id' not in session:
        flash('Por favor, faça login para baixar o PDF.', 'error')
        return redirect(url_for('login'))

    try:
        logging.debug(f"Iniciando geração de PDF para ficha {code}")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM calculos WHERE codigo_ficha = ? AND user_id = ?', 
                       (code, session['user_id']))
        ficha = cursor.fetchone()

        if not ficha:
            conn.close()
            flash('Ficha não encontrada ou você não tem acesso a ela.', 'error')
            return redirect(url_for('historico'))

        colunas = [desc[0] for desc in cursor.description]
        ficha_dict = dict(zip(colunas, ficha))
        conn.close()

        logging.debug(f"Gerando PDF para ficha {code}: {ficha_dict}")

        campos_json = ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 
                       'historia_obstetrica', 'condicoes_gestacionais']
        mapped_data = {}
        for campo in campos_json:
            try:
                raw_value = ficha_dict.get(campo)
                logging.debug(f"Processando {campo} com valor bruto: {raw_value} (tipo: {type(raw_value)})")
                items = []
                if raw_value and isinstance(raw_value, str) and raw_value.strip():
                    try:
                        items = json.loads(raw_value)
                        if not isinstance(items, list):
                            items = [items] if items else []
                        items = [str(item).strip() for item in items if item and str(item).strip()]
                    except json.JSONDecodeError as e:
                        logging.warning(f"JSON inválido para {campo}: {raw_value} - {str(e)}")
                        items = [raw_value.strip()] if raw_value.strip() else []
                mapped_items = []
                for item in items:
                    mapped_item = map_item(campo, item)
                    if mapped_item and mapped_item != "Item Não Informado":
                        mapped_items.append(mapped_item)
                    else:
                        logging.debug(f"Ignorando item inválido para {campo}: {item}")
                mapped_data[campo] = mapped_items
                logging.debug(f"Itens mapeados para {campo}: {mapped_data[campo]}")
            except Exception as e:
                logging.error(f"Erro ao processar {campo}: {str(e)}")
                mapped_data[campo] = []

        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4

        margin_left = 2 * cm
        margin_right = 2 * cm
        margin_top = 1.5 * cm
        margin_bottom = 2 * cm
        max_width = width - margin_left - margin_right

        def check_page_space(c, y_position, required_space):
            if y_position < margin_bottom + required_space:
                logging.warning("Espaço insuficiente na página. Compactando conteúdo.")
                return y_position
            return y_position

        def draw_page_border():
            c.setStrokeColorRGB(0.2, 0.2, 0.2)
            c.setLineWidth(0.5)
            c.rect(
                margin_left - 10, 
                margin_bottom - 10, 
                width - margin_left - margin_right + 20, 
                height - margin_top - margin_bottom + 20
            )

        def draw_footer(page_number):
            c.saveState()
            try:
                c.setFont('Helvetica', 8)
            except Exception as e:
                logging.warning(f"Erro ao definir fonte Helvetica: {str(e)}")
                c.setFont('Helvetica', 8)
            c.setFillColorRGB(0.5, 0.5, 0.5)
            footer_text = f"Página {page_number} | Gerado por Sistema de Classificação de Risco - SES/PB"
            c.drawCentredString(width / 2, margin_bottom - 20, footer_text)
            c.setStrokeColorRGB(0.7, 0.7, 0.7)
            c.setLineWidth(0.3)
            c.line(margin_left, margin_bottom - 5, width - margin_right, margin_bottom - 5)
            c.restoreState()

        def draw_text(c, text, x, y, font='Helvetica', font_size=9, max_width=None, centered=False):
            if not text or not isinstance(text, str):
                text = "Não informado"
            try:
                c.setFont(font, font_size)
            except Exception as e:
                logging.warning(f"Erro ao definir fonte {font}: {str(e)}. Usando Helvetica.")
                c.setFont('Helvetica', font_size)
            if centered:
                c.drawCentredString(x, y, text)
                return y - (font_size + 2) - 5
            if max_width:
                words = text.split()
                lines = []
                current_line = []
                for word in words:
                    current_line.append(word)
                    test_line = ' '.join(current_line)
                    if c.stringWidth(test_line, font, font_size) > max_width:
                        current_line.pop()
                        lines.append(' '.join(current_line))
                        current_line = [word]
                if current_line:
                    lines.append(' '.join(current_line))
                for i, line in enumerate(lines):
                    c.drawString(x, y - i * (font_size + 2), line)
                return y - len(lines) * (font_size + 2) - 5
            else:
                c.drawString(x, y, text)
                return y - (font_size + 1) - 5

        total_pages = 1
        y_position = height - margin_top

        logo_path = os.path.join('static', 'imagens', 'logo.png')
        if os.path.exists(logo_path):
            img = Image(logo_path)
            img_width = 100
            img_height = img_width * (img.imageHeight / img.imageWidth)
            c.drawImage(logo_path, (width - img_width) / 2, y_position - img_height, 
                        width=img_width, height=img_height, mask='auto')
            y_position -= img_height + 10
        else:
            y_position -= 10

        y_position = check_page_space(c, y_position, 60)
        c.setFillColorRGB(0.9, 0.9, 0.9)
        c.setStrokeColorRGB(0.5, 0.5, 0.5)
        c.setLineWidth(0.5)
        c.rect(margin_left, y_position - 40, max_width, 40, fill=1, stroke=1)
        c.setFillColorRGB(0, 0, 0)
        y_position = draw_text(c, "SECRETARIA DE ESTADO DA SAÚDE DA PARAÍBA", 
                              width / 2, y_position - 12, font='Helvetica', font_size=12, centered=True)
        y_position = draw_text(c, "INSTRUMENTO DE CLASSIFICAÇÃO DE RISCO GESTACIONAL - APS", 
                              width / 2, y_position, font='Helvetica', font_size=10, centered=True)
        y_position -= 10
        draw_page_border()

        y_position = check_page_space(c, y_position, 40)
        c.setFillColorRGB(0.9, 0.9, 0.9)
        c.rect(margin_left, y_position - 20, max_width, 20, fill=1, stroke=1)
        c.setFillColorRGB(0, 0, 0)
        y_position = draw_text(c, "Dados da Gestante", margin_left + 10, y_position - 12, 
                              font='Helvetica', font_size=10, max_width=max_width - 20)
        c.setStrokeColorRGB(0.7, 0.7, 0.7)
        c.line(margin_left, y_position, width - margin_right, y_position)
        y_position -= 15

        dados_basicos = [
            f"Nome: {ficha_dict.get('nome_gestante', 'Não informado')}",
            f"Data de Nascimento: {ficha_dict.get('data_nasc', 'Não informado')}",
            f"Telefone: {ficha_dict.get('telefone', 'Não informado')}",
            f"Município: {ficha_dict.get('municipio', 'Não informado')}",
            f"UBS: {ficha_dict.get('ubs', 'Não informado')}",
            f"ACS: {ficha_dict.get('acs', 'Não informado')}",
            f"Período Gestacional: {ficha_dict.get('periodo_gestacional', 'Não informado')}",
            f"Data de Envio: {ficha_dict.get('data_envio', 'Não informado')}",
            f"Código da Ficha: {ficha_dict.get('code', 'Não informado')}",
            f"IMC: {ficha_dict.get('imc', 'Não informado') if ficha_dict.get('imc') is not None else 'Não informado'}",
            f"Profissional: {ficha_dict.get('profissional', '')}"
        ]

        col1_width = max_width / 2 - 10
        col2_width = col1_width
        col1_x = margin_left + 10
        col2_x = margin_left + col1_width + 20
        halfway = len(dados_basicos) // 2 + 1
        y_col1 = y_position
        y_col2 = y_position
        col1_items = dados_basicos[:halfway]
        col2_items = dados_basicos[halfway:]

        for i in range(max(len(col1_items), len(col2_items))):
            y_position = check_page_space(c, min(y_col1, y_col2), 10)
            if y_position != min(y_col1, y_col2):
                y_col1 = y_position
                y_col2 = y_position
            if i < len(col1_items):
                y_col1 = draw_text(c, col1_items[i], col1_x, y_col1, font='Helvetica', font_size=8, max_width=col1_width)
            if i < len(col2_items):
                y_col2 = draw_text(c, col2_items[i], col2_x, y_col2, font='Helvetica', font_size=8, max_width=col2_width)

        y_position = min(y_col1, y_col2) - 15

        secoes = [
            ("1. Características Individuais, Condições Socioeconômicas e Familiares", mapped_data['caracteristicas']),
            ("2. Avaliação Nutricional", mapped_data['avaliacao_nutricional']),
            ("3. Comorbidades Prévias à Gestação Atual", mapped_data['comorbidades']),
            ("4. História Obstétrica", mapped_data['historia_obstetrica']),
            ("5. Condições Gestacionais Atuais", mapped_data['condicoes_gestacionais'])
        ]

        for titulo, itens in secoes:
            y_position = check_page_space(c, y_position, 30)
            c.setFillColorRGB(0.9, 0.9, 0.9)
            c.rect(margin_left, y_position - 18, max_width, 18, fill=1, stroke=1)
            c.setFillColorRGB(0, 0, 0)
            y_position = draw_text(c, titulo, margin_left + 10, y_position - 10, 
                                  font='Helvetica', font_size=9, max_width=max_width - 20)
            c.setStrokeColorRGB(0.7, 0.7, 0.7)
            c.line(margin_left, y_position, width - margin_right, y_position)
            y_position -= 15

            if itens:
                for item in itens:
                    y_position = check_page_space(c, y_position, 15)
                    try:
                        c.setFont('Helvetica', 8)
                    except:
                        c.setFont('Helvetica', 8)
                    bullet_y = y_position - 3
                    c.circle(margin_left + 12, bullet_y, 1.5, stroke=1, fill=1)
                    y_position = draw_text(c, item, margin_left + 20, y_position, 
                                          font='Helvetica', font_size=8, max_width=max_width - 20)
            else:
                y_position = draw_text(c, "Nenhum item selecionado.", margin_left + 20, y_position, 
                                      font='Helvetica', font_size=8, max_width=max_width - 20)
            y_position -= 10

        y_position = check_page_space(c, y_position, 40)
        c.setFillColorRGB(0.9, 0.9, 0.9)
        c.rect(margin_left, y_position - 18, max_width, 18, fill=1, stroke=1)
        c.setFillColorRGB(0, 0, 0)
        y_position = draw_text(c, "Resultado", margin_left + 10, y_position - 10, 
                              font='Helvetica', font_size=9, max_width=max_width - 20)
        c.setStrokeColorRGB(0.7, 0.7, 0.7)
        c.line(margin_left, y_position, width - margin_right, y_position)
        y_position -= 15
        y_position = draw_text(c, f"Pontuação Total: {ficha_dict.get('pontuacao_total', '0')}", 
                              margin_left + 10, y_position, font='Helvetica', font_size=9, max_width=max_width - 10)
        y_position = draw_text(c, f"Classificação de Risco: {ficha_dict.get('classificacao_risco', 'Não informado')}", 
                              margin_left + 10, y_position, font='Helvetica', font_size=9, max_width=max_width - 10)

        draw_footer(total_pages)
        c.save()
        buffer.seek(0)

        debug_pdf_path = f"debug_ficha_{code}.pdf"
        try:
            with open(debug_pdf_path, "wb") as f:
                f.write(buffer.getvalue())
            logging.debug(f"PDF salvo para depuração em: {debug_pdf_path}, tamanho: {len(buffer.getvalue())} bytes")
        except Exception as e:
            logging.warning(f"Erro ao salvar PDF de depuração: {str(e)}")

        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"ficha_{code}.pdf",
            mimetype='application/pdf'
        )

    except sqlite3.OperationalError as e:
        if conn:
            conn.close()
        logging.error(f"Erro no banco de dados ao gerar PDF para ficha {code}: {str(e)}")
        flash('Erro ao acessar o banco de dados.', 'error')
        return redirect(url_for('historico'))
    except Exception as e:
        if conn:
            conn.close()
        logging.exception(f"Erro ao gerar PDF para ficha {code}: {str(e)}")
        flash('Erro ao gerar o PDF.', 'error')
        return redirect(url_for('historico'))

if __name__ == '__main__':
    print(app.url_map)
    app.run(debug=True)