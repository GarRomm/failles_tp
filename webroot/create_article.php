<?php
// create_article.php - Création d'un article
require 'auth.php';

// on laisse pas les non-connectés accéder — OWASP A01
if (!isLoggedIn()) {
    header("Location: login.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // token CSRF obligatoire — OWASP A01
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = "Requête invalide (CSRF).";
        header("Location: create_article.php");
        exit;
    }

    $title   = trim($_POST['title'] ?? '');
    $content = trim($_POST['content'] ?? '');
    // cast (int) sur l'ID de session, pas de risque mais bonne pratique
    $user_id = (int) $_SESSION['user_id'];

    // validation basique, on refuse les champs vides
    if ($title === '' || $content === '') {
        $_SESSION['error'] = "Le titre et le contenu sont requis.";
        header("Location: create_article.php");
        exit;
    }

    // requête préparée — OWASP A03 Injection SQL
    $stmt = $conn->prepare("INSERT INTO articles (user_id, title, content) VALUES (?, ?, ?)");
    $stmt->bind_param('iss', $user_id, $title, $content);

    if ($stmt->execute()) {
        $_SESSION['message'] = "Article créé avec succès.";
        $stmt->close();
        header("Location: index.php");
        exit;
    } else {
        error_log("Erreur article : " . $stmt->error); // log serveur — OWASP A09
        $_SESSION['error'] = "Une erreur est survenue.";
    }
    $stmt->close();
}

// token CSRF pour le formulaire
$csrf = generateCsrfToken();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Créer un Article - BlogSecure</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
        header { background-color: #333; color: white; padding: 20px; text-align: center; }
        nav { background-color: #444; padding: 10px; text-align: center; }
        nav a { color: white; margin: 0 15px; text-decoration: none; }
        nav a:hover { text-decoration: underline; }
        .container { max-width: 600px; margin: 20px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h2 { margin-bottom: 20px; color: #333; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-family: Arial; }
        textarea { resize: vertical; }
        button { padding: 10px 20px; background-color: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; margin-top: 10px; }
        button:hover { background-color: #218838; }
        .error { color: #dc3545; padding: 10px; background-color: #f8d7da; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <header><h1>BlogSecure</h1></header>
    <nav>
        <a href="index.php">Accueil</a>
        <!-- déconnexion en POST + CSRF, un lien GET c'est trop facile à exploiter — OWASP A01 -->
        <form method="POST" action="auth.php" style="display:inline;">
            <input type="hidden" name="logout" value="1">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf); ?>">
            <button type="submit" style="background:none;border:none;color:white;cursor:pointer;font-size:1em;padding:0;margin:0 15px;">Déconnexion</button>
        </form>
    </nav>
    <div class="container">
        <h2>Créer un nouvel article</h2>
        <?php if (isset($_SESSION['error'])): ?>
            <!-- htmlspecialchars pour pas afficher du HTML brut — OWASP A03 XSS -->
            <div class="error"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
        <?php endif; ?>
        <form method="POST" action="">
            <!-- token CSRF injecté dans le form — OWASP A01 -->
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf); ?>">
            <div class="form-group">
                <label for="title">Titre:</label>
                <input type="text" id="title" name="title" required>
            </div>
            <div class="form-group">
                <label for="content">Contenu:</label>
                <textarea id="content" name="content" rows="10" required></textarea>
            </div>
            <button type="submit">Publier l'article</button>
        </form>
    </div>
</body>
</html>
