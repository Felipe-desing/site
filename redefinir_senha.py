<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Redefinir Senhas - Administrador</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f2eabc;
      margin: 0;
      display: flex;
      height: 100vh;
    }

    .left {
      background-color: #194756;
      color: #f2eabc;
      flex: 1;
      padding: 60px 30px;
      display: flex;
      flex-direction: column;
      justify-content: center;
      border-top-right-radius: 0;
      border-bottom-right-radius: 0;
    }

    .left h1 {
      font-size: 2rem;
      margin: 0;
    }

    .left p {
      font-size: 1.2rem;
      margin-top: 10px;
    }

    .right {
      flex: 2;
      padding: 40px;
      overflow-y: auto;
      max-height: 100vh;
      box-sizing: border-box;
    }

    .container {
      background-color: #f2eabc;
      border-radius: 12px;
      padding: 30px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }

    .flash-message {
      padding: 10px;
      margin-bottom: 20px;
      border-radius: 6px;
      text-align: center;
    }

    .flash-message.success {
      background-color: #e6f0e5;
      color: #194756;
    }

    .flash-message.danger {
      background-color: #f2eabc;
      color: #194756;
    }

    h2 {
      color: #54736e;
      margin-top: 20px;
    }

    label {
      display: block;
      margin-top: 10px;
      font-weight: bold;
    }

    label.required::after {
      content: '*';
      color: #194756;
      margin-left: 5px;
    }

    input {
      width: 100%;
      padding: 8px;
      margin-top: 5px;
      margin-bottom: 10px;
      border-radius: 6px;
      border: 1px solid #54736e;
      box-sizing: border-box;
    }

    .button {
      background-color: #54736e;
      color: #f2eabc;
      padding: 10px 20px;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 1rem;
      text-decoration: none;
      text-align: center;
      display: inline-block;
    }

    .button:hover {
      background-color: #0f2b36;
    }

    .logout-button {
      background-color: #d32f2f;
    }

    .logout-button:hover {
      background-color: #b71c1c;
    }

    .button-container {
      display: flex;
      gap: 10px;
      margin-top: 10px;
    }

    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.5);
      justify-content: center;
      align-items: center;
      z-index: 1000;
    }

    .modal-content {
      background-color: #f2eabc;
      padding: 20px;
      border-radius: 8px;
      width: 400px;
      text-align: center;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.3);
    }

    .modal-content p {
      margin: 0 0 20px;
      color: #194756;
    }

    .modal-content button {
      background-color: #54736e;
      color: #f2eabc;
      padding: 10px 20px;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      margin: 0 10px;
    }

    .modal-content button:hover {
      background-color: #0f2b36;
    }
  </style>
</head>
<body>
  <div class="left">
    <h1>Redefinir Senhas</h1>
    <p>Altere senhas de usuários do sistema</p>
  </div>

  <div class="right">
    <div class="container">
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="flash-message {{ category }}">{{ message }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}

      <h2>Redefinir Senha de Usuário</h2>
      <form id="reset-senha-form" action="{{ url_for('admin_reset_senha') }}" method="POST">
        <label class="required">E-mail do Usuário</label>
        <input type="email" name="email" required placeholder="Digite o e-mail do usuário">
        
        <label class="required">Nova Senha</label>
        <input type="password" name="nova_senha" required placeholder="Digite a nova senha">
        
        <div class="button-container">
          <button type="submit" class="button">Redefinir Senha</button>
          <a href="{{ url_for('calculadora') }}" class="button">Voltar para a Calculadora</a>
          <a href="{{ url_for('logout') }}" class="button logout-button">Sair</a>
        </div>
      </form>
    </div>
  </div>

  <div class="modal" id="error-modal">
    <div class="modal-content">
      <p id="error-message"></p>
      <button onclick="closeErrorModal()">Fechar</button>
    </div>
  </div>

  <script>
    // Exibe o modal de erro com mensagem
    function showErrorModal(message) {
      document.getElementById('error-message').innerHTML = message;
      document.getElementById('error-modal').style.display = 'flex';
    }

    // Fecha o modal de erro
    function closeErrorModal() {
      document.getElementById('error-modal').style.display = 'none';
    }

    // Validação do formulário de redefinição de senha
    document.getElementById('reset-senha-form').addEventListener('submit', function(event) {
      const email = document.querySelector('input[name="email"]').value;
      const novaSenha = document.querySelector('input[name="nova_senha"]').value;

      if (!email.trim()) {
        event.preventDefault();
        showErrorModal('O campo E-mail é obrigatório.');
        return;
      }

      if (!novaSenha.trim()) {
        event.preventDefault();
        showErrorModal('O campo Nova Senha é obrigatório.');
        return;
      }

      if (novaSenha.length < 6) {
        event.preventDefault();
        showErrorModal('A nova senha deve ter pelo menos 6 caracteres.');
        return;
      }
    });
  </script>
</body>
</html>