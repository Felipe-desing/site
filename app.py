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
    'placenta_previa': 'Placenta Prévia após 28 semanas',
    'anemia_grave': 'Anemia não responsiva à tratamento (Hb≤ 8) e hemopatia',
    'citologia_anormal': 'Citologia Cervical anormal (LIEAG) – Encaminhar para PTGI',
    'tireoide_gestacao': 'Doenças da tireoide diagnosticada na gestação',
    'diabetes_gestacional_atual': 'Diabetes gestacional',
    'doenca_hipertensiva': 'Doença Hipertensiva na Gestação (Pré-eclâmpsia, Hipertensão gestacional e Pré-eclâmpsia superposta)',
    'doppler_anormal': 'Alteração no doppler das Artérias uterinas (aumento da resistência) e/ou alto risco para Pré-eclâmpsia',
    'doenca_hemolitica': 'Doença Hemolítica',
    'gemelar': 'Gemelar',
    'isoimunizacao_rh': 'Isoimunização Rh',
    'insuficiencia_istmo_atual': 'Insuficiência Istmo cervical',
    'colo_curto': 'Colo curto no morfológico 2T',
    'malformacao_congenita': 'Malformação Congênita Fetal',
    'neoplasia_cancer': 'Neoplasia ginecológica ou Câncer diagnosticado na gestação',
    'polidramnio_oligodramnio': 'Polidrâmnio/Oligodrâmnio',
    'restricao_crescimento_atual': 'Restrição de crescimento fetal Intrauterino',
    'toxoplasmose': 'Toxoplasmose',
    'sifilis_complicada': 'Sífilis terciária, Alterações ultrassonográficas sugestivas de sífilis neonatal ou resistência ao tratamento com Penicilina Benzatina',
    'infeccao_urinaria_repeticao': 'Infecção Urinária de repetição (pielonefrite ou ITU≥3x)',
    'hiv_htlv_hepatites': 'HIV, HTLV ou Hepatites Agudas',
    'condiloma_acuminado': 'Condiloma acuminado (no canal vaginal/colo ou lesões extensas em região genital/perianal) – Encaminhar para PTGI',
    'feto_percentil': 'Feto com percentil > P90 (GIG) ou entre P3 e P10, com doppler normal (PIG)',
    'hepatopatias': 'Hepatopatias (colestase ou aumento das transaminases)',
    'hanseníase': 'Hanseníase diagnosticada na gestação',
    'tuberculose_gestacao': 'Tuberculose diagnosticada na gestação',
    'dependencia_drogas_atual': 'Dependência e/ou uso abusivo de drogas lícitas e ilícitas'
}

def get_db_connection():
    conn = sqlite3.connect('banco.db')
    conn.row_factory = sqlite3.Row
    return conn

def draw_wrapped_text(canvas, text, x, y, max_width, font='Helvetica', font_size=9):
    """
    Desenha texto com quebra de linha e garante um espaço mínimo de 1 cm entre o início da última linha de um texto
    e o início do próximo texto.
    Permite especificar a fonte (ex.: 'Poppins', 'Poppins-Bold', 'Helvetica', 'Helvetica-Bold') e o tamanho da fonte.
    Retorna a nova posição y após desenhar o texto.
    """
    if not text or not isinstance(text, str) or not text.strip():
        text = "Não informado"
    
    # Configurações do texto
    try:
        canvas.setFont(font, font_size)
        logging.debug(f"Fonte definida: {font}, tamanho: {font_size} para texto: {text[:50]}...")
    except Exception as e:
        logging.error(f"Erro ao definir fonte {font}: {str(e)}. Usando Helvetica como fallback.")
        canvas.setFont('Helvetica', font_size)

    lines = []
    current_line = []
    words = text.split()
    
    # Calcular as linhas com base na largura máxima
    for word in words:
        current_line.append(word)
        test_line = ' '.join(current_line)
        if canvas.stringWidth(test_line, font, font_size) > max_width:
            current_line.pop()
            lines.append(' '.join(current_line))
            current_line = [word]
    if current_line:
        lines.append(' '.join(current_line))
    
    # Se não houver linhas, adicionar uma linha vazia para garantir o espaço
    if not lines:
        lines.append('Não informado')
    
    # Desenhar cada linha com um espaço fixo entre as linhas do mesmo texto
    line_spacing = 14  # Espaço entre linhas do mesmo texto
    for i, line in enumerate(lines):
        canvas.drawString(x, y - i * line_spacing, line)
    
    # Calcular a nova posição y
    total_lines = len(lines)
    total_text_height = total_lines * line_spacing
    new_y = y - total_text_height - 28.35  # 1 cm abaixo da última linha
    
    return new_y

def map_item(campo, item):
    """
    Mapeia um item para seu rótulo legível usando dicionários globais.
    Retorna o item original se não mapeado.
    """
    if not item or not isinstance(item, str):
        logging.warning(f"Item inválido para {campo}: {item}")
        return "Item Inválido"
    
    item = item.strip()
    # Tentar desserializar se for uma string JSON
    try:
        parsed_item = json.loads(item)
        if isinstance(parsed_item, list):
            # Se for uma lista, usar o primeiro item
            item = parsed_item[0] if parsed_item else item
        elif parsed_item:
            item = parsed_item
    except json.JSONDecodeError:
        pass  # Usar item como está se não for JSON

    mapping = {
        'caracteristicas': CARACTERISTICAS_MAP,
        'avaliacao_nutricional': AVALIACAO_NUTRICIONAL_MAP,
        'comorbidades': COMORBIDADES_MAP,
        'historia_obstetrica': HISTORIA_OBSTETRICA_MAP,
        'condicoes_gestacionais': CONDICOES_GESTACIONAIS_MAP
    }.get(campo, {})
    mapped_item = mapping.get(item, item)
    if mapped_item == item:
        logging.warning(f"Item não mapeado para {campo}: {item}")
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
            cursor.execute('SELECT is_admin FROM usuarios WHERE id = ?', (session['user_id'],))
            user = cursor.fetchone()
            conn.close()
            if not user or not user['is_admin']:
                flash('Acesso negado. Apenas administradores podem acessar esta página.', 'error')
                return redirect(url_for('calculadora'))
            return f(*args, **kwargs)
        except sqlite3.OperationalError as e:
            flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
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
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
            user = cursor.fetchone()
            conn.close()

            if user and bcrypt.checkpw(senha.encode('utf-8'), user['senha'].encode('utf-8')) and user['approved']:
                session['user_id'] = user['id']
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('calculadora'))
            else:
                flash('Email, senha inválidos ou conta não aprovada.', 'error')
        except sqlite3.OperationalError as e:
            flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
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
                INSERT INTO usuarios (nome, cpf, profissao, telefone, email, municipio, cnes, senha, is_admin, approved)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (nome, cpf, profissao, telefone, email, municipio, cnes, senha_hash, 0, 0))
            conn.commit()
            conn.close()
            flash('Cadastro realizado com sucesso! Aguarde aprovação.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('E-mail ou CPF já cadastrado.', 'error')
            return redirect(url_for('register'))
        except sqlite3.OperationalError as e:
            flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
            return redirect(url_for('register'))
        except Exception as e:
            flash(f'Erro ao cadastrar: {str(e)}', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

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
            flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
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
            cursor.execute('SELECT * FROM calculos WHERE codigo_ficha = ?', (codigo_ficha,))
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
            flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
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
        # Logar todos os dados recebidos para depuração
        logging.debug(f"Dados recebidos do formulário: {request.form}")

        # Capturar campos do formulário
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

        # Capturar campos JSON (enviados como strings JSON)
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

        # Logar listas após desserialização
        logging.debug(f"Características: {caracteristicas}")
        logging.debug(f"Avaliação Nutricional: {avaliacao_nutricional}")
        logging.debug(f"Comorbidades: {comorbidades}")
        logging.debug(f"História Obstétrica: {historia_obstetrica}")
        logging.debug(f"Condições Gestacionais: {condicoes_gestacionais}")

        # Conectar ao banco e obter o profissional
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT nome FROM usuarios WHERE id = ?', (session['user_id'],))
        usuario = cursor.fetchone()
        if not usuario:
            conn.close()
            return jsonify({'success': False, 'message': 'Usuário não encontrado.'}), 400
        profissional = usuario['nome']

        # Validar campos obrigatórios
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

        # Validar pontuação total
        try:
            pontuacao_total = int(pontuacao_total) if pontuacao_total and pontuacao_total.strip() else 0
        except (ValueError, TypeError):
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Pontuação total inválida.'
            }), 400

        # Validar formato de data
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

        # Serializar listas como JSON
        caracteristicas_json = json.dumps(caracteristicas)
        avaliacao_nutricional_json = json.dumps(avaliacao_nutricional)
        comorbidades_json = json.dumps(comorbidades)
        historia_obstetrica_json = json.dumps(historia_obstetrica)
        condicoes_gestacionais_json = json.dumps(condicoes_gestacionais)

        # Logar JSONs salvos
        logging.debug(f"JSON salvo - Características: {caracteristicas_json}")
        logging.debug(f"JSON salvo - Avaliação Nutricional: {avaliacao_nutricional_json}")
        logging.debug(f"JSON salvo - Comorbidades: {comorbidades_json}")
        logging.debug(f"JSON salvo - História Obstétrica: {historia_obstetrica_json}")
        logging.debug(f"JSON salvo - Condições Gestacionais: {condicoes_gestacionais_json}")

        # Gerar código da ficha
        codigo_ficha = str(uuid.uuid4())[:8].upper()

        # Inserir no banco de dados
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
        nome_gestante = data.get('nome_gestante', '').strip()
        municipio = data.get('municipio', '').strip()

        if not nome_gestante or not municipio:
            return jsonify({
                'success': False,
                'message': 'Nome da gestante e município são obrigatórios.'
            }), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        query = '''
            SELECT codigo_ficha, nome_gestante, data_envio, periodo_gestacional, 
                   pontuacao_total, classificacao_risco, municipio, ubs, acs, profissional
            FROM calculos 
            WHERE user_id = ? AND nome_gestante LIKE ? AND municipio LIKE ?
        '''
        cursor.execute(query, (session['user_id'], f'%{nome_gestante}%', f'%{municipio}%'))
        fichas = cursor.fetchall()
        conn.close()

        fichas_list = [dict(ficha) for ficha in fichas]

        if not fichas_list:
            return jsonify({
                'success': True,
                'fichas': [],
                'message': 'Nenhum registro encontrado para os dados informados.'
            })

        return jsonify({
            'success': True,
            'fichas': fichas_list,
            'message': f'{len(fichas_list)} registro(s) encontrado(s).'
        })

    except sqlite3.OperationalError as e:
        logging.error(f"Erro no banco de dados: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erro no banco de dados: {str(e)}'
        }), 500
    except Exception as e:
        logging.error(f"Erro ao buscar histórico: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erro ao buscar o histórico: {str(e)}'
        }), 500

@app.route('/obter_ficha_completa', methods=['POST'])
def obter_ficha_completa():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Por favor, faça login para acessar a ficha.'}), 401

    try:
        data = request.get_json()
        codigo_ficha = data.get('codigo_ficha')

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

        # Logar valores brutos do banco
        logging.debug(f"Valores brutos para ficha {codigo_ficha}:")
        for field in ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 'historia_obstetrica', 'condicoes_gestacionais']:
            logging.debug(f"{field} (raw): {ficha_dict[field]}")

        # Desserializar campos JSON
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
                        # Tratar JSON aninhado
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

        # Logar valores após desserialização
        logging.debug(f"Valores após desserialização para ficha {codigo_ficha}:")
        for field in ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 'historia_obstetrica', 'condicoes_gestacionais']:
            logging.debug(f"{field} (parsed): {ficha_dict[field]}")

        # Mapear valores para rótulos legíveis
        ficha_dict['caracteristicas'] = [map_item('caracteristicas', item) for item in ficha_dict['caracteristicas'] if item]
        ficha_dict['avaliacao_nutricional'] = [map_item('avaliacao_nutricional', item) for item in ficha_dict['avaliacao_nutricional'] if item]
        ficha_dict['comorbidades'] = [map_item('comorbidades', item) for item in ficha_dict['comorbidades'] if item]
        ficha_dict['historia_obstetrica'] = [map_item('historia_obstetrica', item) for item in ficha_dict['historia_obstetrica'] if item]
        ficha_dict['condicoes_gestacionais'] = [map_item('condicoes_gestacionais', item) for item in ficha_dict['condicoes_gestacionais'] if item]

        # Logar valores após mapeamento
        logging.debug(f"Valores após mapeamento para ficha {codigo_ficha}:")
        for field in ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 'historia_obstetrica', 'condicoes_gestacionais']:
            logging.debug(f"{field} (mapped): {ficha_dict[field]}")

        return jsonify({'ficha': ficha_dict}), 200

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
        return jsonify({'success': True, 'message': 'Logout realizado com sucesso.'})
    return jsonify({'success': False, 'message': 'Nenhuma sessão ativa.'}), 401

@app.route('/admin/approve', methods=['GET'])
@admin_required
def admin_approve():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, nome, email, municipio, profissao, cnes, approved FROM usuarios WHERE approved = 0')
        usuarios = [dict(user) for user in cursor.fetchall()]
        conn.close()
        return render_template('admin_approve.html', usuarios=usuarios)
    except sqlite3.OperationalError as e:
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
        return redirect(url_for('calculadora'))

@app.route('/admin/aprovar_usuario', methods=['POST'])
@admin_required
def admin_aprovar_usuario():
    usuario_id = request.form.get('usuario_id')
    if not usuario_id:
        flash('ID do usuário inválido.', 'danger')
        return redirect(url_for('admin_approve'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET approved = 1 WHERE id = ?', (usuario_id,))
        if cursor.rowcount == 0:
            flash('Usuário não encontrado.', 'danger')
        else:
            conn.commit()
            flash('Usuário aprovado com sucesso.', 'success')
        conn.close()
    except sqlite3.OperationalError as e:
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
    return redirect(url_for('admin_approve'))

@app.route('/admin/rejeitar_usuario', methods=['POST'])
@admin_required
def admin_rejeitar_usuario():
    usuario_id = request.form.get('usuario_id')
    if not usuario_id:
        flash('ID do usuário inválido.', 'danger')
        return redirect(url_for('admin_approve'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM usuarios WHERE id = ?', (usuario_id,))
        if cursor.rowcount == 0:
            flash('Usuário não encontrado.', 'danger')
        else:
            conn.commit()
            flash('Usuário rejeitado e removido.', 'success')
        conn.close()
    except sqlite3.OperationalError as e:
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
    return redirect(url_for('admin_approve'))

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
        flash('E-mail e nova senha são obrigatórios.', 'danger')
        return redirect(url_for('admin_senha'))

    if len(nova_senha) < 6:
        flash('A nova senha deve ter pelo menos 6 caracteres.', 'danger')
        return redirect(url_for('admin_senha'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM usuarios WHERE email = ?', (email,))
        user = cursor.fetchone()

        if not user:
            flash('Usuário não encontrado.', 'danger')
            conn.close()
            return redirect(url_for('admin_senha'))

        nova_senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('UPDATE usuarios SET senha = ? WHERE email = ?', (nova_senha_hash, email))
        conn.commit()
        conn.close()
        flash('Senha redefinida com sucesso.', 'success')
        return redirect(url_for('admin_senha'))
    except sqlite3.OperationalError as e:
        flash(f'Erro no banco de dados: {str(e)}. Contate o administrador.', 'danger')
        return redirect(url_for('admin_senha'))

@app.route('/admin/relatorio', methods=['GET', 'POST'])
@admin_required
def admin_relatorio():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT DISTINCT municipio FROM calculos ORDER BY municipio')
        municipios = [row['municipio'] for row in cursor.fetchall()]

        registros = []
        filtro_municipio = None

        # Consulta base para registros
        if request.method == 'POST':
            filtro_municipio = request.form.get('municipio')
            query = '''
                SELECT user_id, codigo_ficha, nome_gestante, data_nasc, telefone, municipio, ubs, acs,
                       periodo_gestacional, data_envio, pontuacao_total, classificacao_risco, imc,
                       caracteristicas, avaliacao_nutricional, comorbidades, historia_obstetrica,
                       condicoes_gestacionais, profissional
                FROM calculos
                WHERE municipio = ? ORDER BY data_envio DESC
            ''' if filtro_municipio else '''
                SELECT user_id, codigo_ficha, nome_gestante, data_nasc, telefone, municipio, ubs, acs,
                       periodo_gestacional, data_envio, pontuacao_total, classificacao_risco, imc,
                       caracteristicas, avaliacao_nutricional, comorbidades, historia_obstetrica,
                       condicoes_gestacionais, profissional
                FROM calculos ORDER BY data_envio DESC
            '''
            cursor.execute(query, (filtro_municipio,) if filtro_municipio else ())
        else:
            cursor.execute('''
                SELECT user_id, codigo_ficha, nome_gestante, data_nasc, telefone, municipio, ubs, acs,
                       periodo_gestacional, data_envio, pontuacao_total, classificacao_risco, imc,
                       caracteristicas, avaliacao_nutricional, comorbidades, historia_obstetrica,
                       condicoes_gestacionais, profissional
                FROM calculos ORDER BY data_envio DESC
            ''')

        # Processar registros
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
            # Padronizar classificacao_risco
            if registro['classificacao_risco'] and isinstance(registro['classificacao_risco'], str):
                classificacao = registro['classificacao_risco'].strip().lower()
                if classificacao == 'risco habitual':
                    registro['classificacao_risco'] = 'Risco Habitual'
                elif classificacao == 'médio risco':
                    registro['classificacao_risco'] = 'Risco Intermediário'
                elif classificacao == 'alto risco':
                    registro['classificacao_risco'] = 'Risco Alto'
            registros.append(registro)

        # Calcular estatísticas para o relatório quantitativo
        from collections import Counter
        caracteristicas_counts = Counter()
        avaliacao_nutricional_counts = Counter()
        comorbidades_counts = Counter()
        historia_obstetrica_counts = Counter()
        condicoes_gestacionais_counts = Counter()

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

        # Remover entradas '-' dos contadores
        for counter in [caracteristicas_counts, avaliacao_nutricional_counts, comorbidades_counts, 
                        historia_obstetrica_counts, condicoes_gestacionais_counts]:
            if '-' in counter:
                del counter['-']

        total_registros = len(registros)
        municipios_unicos = len(set(registro['municipio'] for registro in registros))
        
        # Distribuição por período gestacional
        periodo_gestacional = Counter(registro['periodo_gestacional'] for registro in registros if registro['periodo_gestacional'])
        
        # Média da pontuação total
        pontuacao_total = [registro['pontuacao_total'] for registro in registros if registro['pontuacao_total'] is not None]
        media_pontuacao = sum(pontuacao_total) / len(pontuacao_total) if pontuacao_total else 0
        
        # Distribuição por classificação de risco
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
            'condicoes_gestacionais_counts': dict(condicoes_gestacionais_counts)
        }

        conn.close()
        return render_template('admin_relatorio.html', municipios=municipios, registros=registros, 
                             filtro_municipio=filtro_municipio, estatisticas=estatisticas)

    except sqlite3.OperationalError as e:
        if conn:
            conn.close()
        flash(f'Erro no banco de dados: {str(e)}.', 'danger')
        return redirect(url_for('calculadora'))
    except Exception as e:
        if conn:
            conn.close()
        logging.error(f"Erro ao carregar relatório: {str(e)}")
        flash(f'Erro ao carregar relatório: {str(e)}.', 'danger')
        return redirect(url_for('calculadora'))

@app.route('/gerar_pdf/<codigo_ficha>')
def gerar_pdf(codigo_ficha):
    if 'user_id' not in session:
        flash('Por favor, faça login para baixar o PDF.', 'error')
        return redirect(url_for('login'))

    try:
        # Conectar ao banco de dados
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM calculos WHERE codigo_ficha = ? AND user_id = ?', (codigo_ficha, session['user_id']))
        ficha = cursor.fetchone()

        if not ficha:
            conn.close()
            flash('Ficha não encontrada ou você não tem acesso a ela.', 'error')
            return redirect(url_for('historico'))

        # Mapear os campos da ficha
        colunas = [desc[0] for desc in cursor.description]
        ficha_dict = dict(zip(colunas, ficha))

        # Logar valores brutos do banco
        logging.debug(f"Valores brutos para ficha {codigo_ficha}:")
        for campo in ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 'historia_obstetrica', 'condicoes_gestacionais']:
            logging.debug(f"{campo}: {ficha_dict[campo]} (tipo: {type(ficha_dict[campo])})")

        # Validar dados do banco
        campos_json = ['caracteristicas', 'avaliacao_nutricional', 'comorbidades', 'historia_obstetrica', 'condicoes_gestacionais']
        for campo in campos_json:
            if not isinstance(ficha_dict[campo], (str, type(None))):
                logging.error(f"Valor inválido para {campo} no banco: {ficha_dict[campo]} (tipo: {type(ficha_dict[campo])})")
                ficha_dict[campo] = ''

        # Desserializar os campos JSON
        raw_data = {}
        for campo in campos_json:
            try:
                raw_value = ficha_dict[campo]
                logging.debug(f"Processando campo {campo} com valor bruto: {raw_value} (tipo: {type(raw_value)})")

                if raw_value is None or raw_value == '':
                    items = []
                elif isinstance(raw_value, str) and raw_value.strip():
                    try:
                        items = json.loads(raw_value)
                        if not isinstance(items, list):
                            items = [items] if items else []
                        if items and isinstance(items, list) and len(items) == 1:
                            try:
                                nested_items = json.loads(items[0]) if isinstance(items[0], str) else items[0]
                                if isinstance(nested_items, list):
                                    items = nested_items
                                elif nested_items:
                                    items = [nested_items]
                            except json.JSONDecodeError:
                                pass
                    except json.JSONDecodeError as e:
                        logging.warning(f"Erro ao desserializar {campo}: {str(e)} - Valor bruto: {raw_value}")
                        items = [raw_value.strip()] if raw_value.strip() else []
                else:
                    logging.warning(f"Valor inesperado para {campo}: {raw_value} (tipo: {type(raw_value)})")
                    items = []

                logging.debug(f"Itens após desserialização para {campo}: {items}")
                raw_data[campo] = items
            except Exception as e:
                logging.error(f"Erro geral ao processar {campo} para ficha {codigo_ficha}: {str(e)}")
                raw_data[campo] = []

        # Mapear os itens
        mapped_data = {}
        for campo in campos_json:
            mapped_data[campo] = []
            items = raw_data[campo]
            for item in items:
                if item and isinstance(item, str) and item.strip():
                    mapped_item = map_item(campo, item)
                    logging.debug(f"Item: {item}, Mapeado para: {mapped_item} (campo: {campo})")
                    mapped_data[campo].append(mapped_item)
                else:
                    logging.warning(f"Item ignorado por ser inválido: {item} (campo: {campo})")

        # Logar dados mapeados
        logging.debug(f"Dados mapeados para ficha {codigo_ficha}:")
        for campo in campos_json:
            logging.debug(f"{campo}: {mapped_data[campo]}")

        # Criar o PDF em memória
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4

        margin_left = 2 * cm
        margin_right = 2 * cm
        margin_top = 2 * cm
        margin_bottom = 3 * cm
        max_width = width - margin_left - margin_right
        line_height = 20

        # Definir a cor do texto como preto
        c.setFillColorRGB(0, 0, 0)

        # Contar número total de páginas (estimativa inicial)
        total_pages = 1

        # Função para desenhar borda da página
        def draw_page_border():
            c.setStrokeColorRGB(0.2, 0.2, 0.2)
            c.setLineWidth(0.5)
            c.rect(margin_left - 10, margin_bottom - 10, width - margin_left - margin_right + 20, height - margin_top - margin_bottom + 20)

        # Função para desenhar rodapé
        def draw_footer(page_number):
            c.saveState()
            c.setFont('Poppins', 8)
            c.setFillColorRGB(0.5, 0.5, 0.5)
            footer_text = f"Página {page_number} | Gerado por Sistema de Classificação de Risco - SES/PB"
            c.drawCentredString(width / 2, margin_bottom - 20, footer_text)
            c.setStrokeColorRGB(0.7, 0.7, 0.7)
            c.setLineWidth(0.3)
            c.line(margin_left, margin_bottom - 10, width - margin_right, margin_bottom - 10)
            c.restoreState()

        # Logo
        logo_path = os.path.join('static', 'imagens', 'logo.png')
        y_position = height - margin_top
        if os.path.exists(logo_path):
            img = Image(logo_path)
            img_width = 120
            img_height = img_width * (img.imageHeight / img.imageWidth)
            c.drawImage(logo_path, (width - img_width) / 2, y_position - img_height, width=img_width, height=img_height, mask='auto')
            y_position -= img_height + 20
        else:
            y_position -= 20

        # Cabeçalho com fundo
        c.setFillColorRGB(0.9, 0.9, 0.9)  # Cinza mais escuro
        c.setStrokeColorRGB(0.5, 0.5, 0.5)  # Borda cinza
        c.setLineWidth(0.5)
        c.rect(margin_left, y_position - 50, max_width, 50, fill=1, stroke=1)  # Altura 50
        c.setFillColorRGB(0, 0, 0)
        c.setFont('Poppins-Bold', 14)
        c.drawCentredString(width / 2, y_position - 15, "SECRETARIA DE ESTADO DA SAÚDE DA PARAÍBA")  # Ajustado para centralizar
        c.setFont('Poppins-Bold', 12)
        c.drawCentredString(width / 2, y_position - 35, "INSTRUMENTO DE CLASSIFICAÇÃO DE RISCO GESTACIONAL - APS")  # Ajustado para centralizar
        y_position -= 70

        # Desenhar borda da página
        draw_page_border()

        # Dados da Gestante (em duas colunas)
        c.setFillColorRGB(0.9, 0.9, 0.9)
        c.setStrokeColorRGB(0.5, 0.5, 0.5)
        c.setLineWidth(0.5)
        c.rect(margin_left, y_position - 24, max_width, 24, fill=1, stroke=1)  # Altura 24
        c.setFillColorRGB(0, 0, 0)
        y_position = draw_wrapped_text(c, "Dados da Gestante", margin_left + 10, y_position - 15, max_width - 20, font='Poppins-Bold', font_size=11)  # Ajustado para centralizar
        c.setStrokeColorRGB(0.7, 0.7, 0.7)
        c.setLineWidth(0.5)
        c.line(margin_left, y_position, width - margin_right, y_position)
        y_position -= line_height

        dados_basicos = [
            f"Nome: {ficha_dict['nome_gestante'] or 'Não informado'}",
            f"Data de Nascimento: {ficha_dict['data_nasc'] or 'Não informado'}",
            f"Telefone: {ficha_dict['telefone'] or 'Não informado'}",
            f"Município: {ficha_dict['municipio'] or 'Não informado'}",
            f"UBS: {ficha_dict['ubs'] or 'Não informado'}",
            f"ACS: {ficha_dict['acs'] or 'Não informado'}",
            f"Período Gestacional: {ficha_dict['periodo_gestacional'] or 'Não informado'}",
            f"Data de Envio: {ficha_dict['data_envio'] or 'Não informado'}",
            f"Código da Ficha: {ficha_dict['codigo_ficha'] or 'Não informado'}",
            f"IMC: {ficha_dict['imc'] if ficha_dict['imc'] is not None else 'Não informado'}",
            f"Profissional: {ficha_dict['profissional'] or 'Não informado'}"
        ]

        # Dividir em duas colunas
        col1_width = max_width / 2 - 10
        col2_width = max_width / 2 - 10
        col1_x = margin_left
        col2_x = margin_left + max_width / 2 + 10
        halfway = len(dados_basicos) // 2 + 1
        y_col1 = y_position
        y_col2 = y_position

        for i, dado in enumerate(dados_basicos):
            if i < halfway:
                if y_col1 < margin_bottom + 50:
                    c.showPage()
                    draw_page_border()
                    draw_footer(total_pages)
                    total_pages += 1
                    y_col1 = height - margin_top
                    y_col2 = y_col1
                    c.setFillColorRGB(0, 0, 0)
                y_col1 = draw_wrapped_text(c, dado, col1_x, y_col1, col1_width, font='Poppins', font_size=9)
            else:
                if y_col2 < margin_bottom + 50:
                    c.showPage()
                    draw_page_border()
                    draw_footer(total_pages)
                    total_pages += 1
                    y_col2 = height - margin_top
                    y_col1 = y_col2
                    c.setFillColorRGB(0, 0, 0)
                y_col2 = draw_wrapped_text(c, dado, col2_x, y_col2, col2_width, font='Poppins', font_size=9)

        y_position = min(y_col1, y_col2) - 30

        # Seções mapeadas
        secoes = [
            ("1. Características Individuais, Condições Socioeconômicas e Familiares", mapped_data['caracteristicas']),
            ("2. Avaliação Nutricional", mapped_data['avaliacao_nutricional']),
            ("3. Comorbidades Prévias à Gestação Atual", mapped_data['comorbidades']),
            ("4. História Obstétrica", mapped_data['historia_obstetrica']),
            ("5. Condições Gestacionais Atuais", mapped_data['condicoes_gestacionais'])
        ]

        for titulo, itens in secoes:
            if y_position < margin_bottom + 60:
                c.showPage()
                draw_page_border()
                draw_footer(total_pages)
                total_pages += 1
                y_position = height - margin_top
                c.setFillColorRGB(0, 0, 0)
            c.setFillColorRGB(0.9, 0.9, 0.9)
            c.setStrokeColorRGB(0.5, 0.5, 0.5)
            c.setLineWidth(0.5)
            c.rect(margin_left, y_position - 24, max_width, 24, fill=1, stroke=1)  # Altura 24
            c.setFillColorRGB(0, 0, 0)
            y_position = draw_wrapped_text(c, titulo, margin_left + 10, y_position - 15, max_width - 20, font='Poppins-Bold', font_size=11)  # Ajustado para centralizar
            c.setStrokeColorRGB(0.7, 0.7, 0.7)
            c.setLineWidth(0.5)
            c.line(margin_left, y_position, width - margin_right, y_position)
            y_position -= line_height

            if itens:
                for item in itens:
                    if y_position < margin_bottom + 50:
                        c.showPage()
                        draw_page_border()
                        draw_footer(total_pages)
                        total_pages += 1
                        y_position = height - margin_top
                        c.setFillColorRGB(0, 0, 0)
                    c.setFillColorRGB(0, 0, 0)
                    c.setFont('Poppins', 9)
                    c.circle(margin_left + 12, y_position - 4, 2, stroke=1, fill=1)
                    y_position = draw_wrapped_text(c, item, margin_left + 20, y_position, max_width - 20, font='Poppins', font_size=9)
            else:
                y_position = draw_wrapped_text(c, "Nenhum item selecionado.", margin_left + 20, y_position, max_width - 20, font='Poppins', font_size=9)
            y_position -= 15

        # Adicionar Resultado, Pontuação e Classificação
        if y_position < margin_bottom + 80:
            c.showPage()
            draw_page_border()
            draw_footer(total_pages)
            total_pages += 1
            y_position = height - margin_top
            c.setFillColorRGB(0, 0, 0)

        c.setFillColorRGB(0.9, 0.9, 0.9)
        c.setStrokeColorRGB(0.5, 0.5, 0.5)
        c.setLineWidth(0.5)
        c.rect(margin_left, y_position - 24, max_width, 24, fill=1, stroke=1)  # Altura 24
        c.setFillColorRGB(0, 0, 0)
        y_position = draw_wrapped_text(c, "Resultado", margin_left + 10, y_position - 15, max_width - 20, font='Poppins-Bold', font_size=11)  # Ajustado para centralizar
        c.setStrokeColorRGB(0.7, 0.7, 0.7)
        c.setLineWidth(0.5)
        c.line(margin_left, y_position, width - margin_right, y_position)
        y_position -= line_height
        y_position = draw_wrapped_text(c, f"Pontuação Total: {ficha_dict['pontuacao_total'] if ficha_dict['pontuacao_total'] is not None else '0'}", margin_left + 5, y_position, max_width - 10, font='Poppins-Bold', font_size=11)
        y_position = draw_wrapped_text(c, f"Classificação de Risco: {ficha_dict['classificacao_risco'] or 'Não informado'}", margin_left + 5, y_position, max_width - 10, font='Poppins-Bold', font_size=11)

        # Desenhar rodapé na última página
        draw_footer(total_pages)

        # Finalizar e salvar o PDF
        logging.debug(f"Finalizando PDF para ficha {codigo_ficha}")
        c.save()
        buffer.seek(0)
        logging.debug(f"Buffer do PDF preparado para envio, tamanho: {buffer.getbuffer().nbytes} bytes")

        conn.close()

        return send_file(buffer, as_attachment=True, download_name=f"ficha_{codigo_ficha}.pdf", mimetype='application/pdf')

    except sqlite3.OperationalError as e:
        conn.close()
        logging.error(f"Erro no banco de dados ao gerar PDF para ficha {codigo_ficha}: {str(e)}")
        flash('Ocorreu um erro ao gerar o PDF.', 'error')
        return redirect(url_for('historico'))
    except Exception as e:
        conn.close()
        logging.exception(f"Erro geral ao gerar o PDF para ficha {codigo_ficha}: {str(e)}")
        flash('Ocorreu um erro ao gerar o PDF.', 'error')
        return redirect(url_for('historico'))

if __name__ == '__main__':
    print(app.url_map)
    app.run(debug=True)