<?php
require 'auth.php';

// si déjà connecté, pas besoin d'être là
if (isLoggedIn()) {
    header("Location: index.php");
    exit;
}

// token CSRF pour protéger le formulaire — OWASP A01
$csrf = generateCsrfToken();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion - BlogSecure</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
        header { background-color: #333; color: white; padding: 20px; text-align: center; }
        nav { background-color: #444; padding: 10px; text-align: center; }
        nav a { color: white; margin: 0 15px; text-decoration: none; }
        nav a:hover { text-decoration: underline; }
        .container { max-width: 400px; margin: 50px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h2 { margin-bottom: 20px; color: #333; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 100%; padding: 10px; background-color: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; margin-top: 10px; }
        button:hover { background-color: #218838; }
        .error { color: #dc3545; padding: 10px; background-color: #f8d7da; border-radius: 4px; margin: 10px 0; }
        .link { margin-top: 15px; text-align: center; }
        .link a { color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <header>
        <h1>BlogSecure</h1>
    </header>
    <nav>
        <a href="index.php">Accueil</a>
        <a href="register.php">Inscription</a>
    </nav>
    <div class="container">
        <h2>Connexion</h2>
        <?php if (isset($_SESSION['error'])): ?>
            <!-- htmlspecialchars pour pas afficher du HTML brut — OWASP A03 XSS -->
            <div class="error"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
        <?php endif; ?>

        <form method="POST" action="auth.php">
            <input type="hidden" name="action" value="login">
            <!-- token CSRF injecté dans le form — OWASP A01 -->
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf); ?>">
            <div class="form-group">
                <label for="username">Nom d'utilisateur:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Mot de passe:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Se connecter</button>
        </form>
        <div class="link">
            <p>Pas encore inscrit ? <a href="register.php">S'inscrire</a></p>
        </div>
    </div>
</body>
</html>
