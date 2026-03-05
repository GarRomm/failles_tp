<?php
// index.php - Page d'accueil et listing des articles
require 'auth.php';

// token CSRF pour les actions de la page (suppression, déconnexion) — OWASP A01
$csrf = generateCsrfToken();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlogSecure - Plateforme de Blog</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
        header { background-color: #333; color: white; padding: 20px; text-align: center; }
        nav { background-color: #444; padding: 10px; text-align: center; }
        nav a { color: white; margin: 0 15px; text-decoration: none; }
        nav a:hover { text-decoration: underline; }
        .container { max-width: 900px; margin: 20px auto; padding: 20px; }
        .article { background: white; margin: 15px 0; padding: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .article h3 { margin-bottom: 10px; color: #333; }
        .article .meta { color: #666; font-size: 0.9em; margin-bottom: 10px; }
        .article p { line-height: 1.6; }
        .btn { display: inline-block; padding: 8px 15px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin-top: 10px; }
        .btn:hover { background-color: #0056b3; }
        .btn.danger { background-color: #dc3545; }
        .btn.danger:hover { background-color: #c82333; }
        button { padding: 10px 20px; background-color: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #218838; }
        .error { color: #dc3545; padding: 10px; background-color: #f8d7da; border-radius: 4px; margin: 10px 0; }
        .success { color: #155724; padding: 10px; background-color: #d4edda; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <header>
        <h1>BlogSecure</h1>
        <p>Plateforme de partage d'articles</p>
    </header>
    <nav>
        <a href="index.php">Accueil</a>
        <?php if (!isLoggedIn()): ?>
            <a href="login.php">Connexion</a>
            <a href="register.php">Inscription</a>
        <?php else: ?>
            <a href="create_article.php">Nouvel Article</a>
            <!-- déconnexion en POST + CSRF, un lien GET c'est trop facile à exploiter — OWASP A01 -->
            <form method="POST" action="auth.php" style="display:inline;">
                <input type="hidden" name="logout" value="1">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf); ?>">
                <button type="submit" style="background:none;border:none;color:white;cursor:pointer;font-size:1em;padding:0;margin:0 15px;">Déconnexion</button>
            </form>
        <?php endif; ?>
    </nav>
    <div class="container">
        <?php
        // htmlspecialchars sur les messages de session — OWASP A03 XSS
        if (isset($_SESSION['message'])) {
            echo '<div class="success">' . htmlspecialchars($_SESSION['message'], ENT_QUOTES, 'UTF-8') . '</div>';
            unset($_SESSION['message']);
        }
        if (isset($_SESSION['error'])) {
            echo '<div class="error">' . htmlspecialchars($_SESSION['error'], ENT_QUOTES, 'UTF-8') . '</div>';
            unset($_SESSION['error']);
        }
        ?>
        <h2>Articles Récents</h2>
        <?php
        // pas de variable user ici, requête statique — pas besoin de prepared statement
        $sql = "SELECT articles.*, users.username FROM articles
                JOIN users ON articles.user_id = users.id
                ORDER BY articles.created_at DESC";
        $result = $conn->query($sql);

        if ($result && $result->num_rows > 0) {
            while ($article = $result->fetch_assoc()) {
                echo '<div class="article">';
                // toutes les sorties passent par htmlspecialchars — OWASP A03 XSS
                echo '<h3>' . htmlspecialchars($article['title'], ENT_QUOTES, 'UTF-8') . '</h3>';
                echo '<div class="meta">Par ' . htmlspecialchars($article['username'], ENT_QUOTES, 'UTF-8') . ' - ' . htmlspecialchars($article['created_at'], ENT_QUOTES, 'UTF-8') . '</div>';
                echo '<p>' . htmlspecialchars($article['content'], ENT_QUOTES, 'UTF-8') . '</p>';
                // cast (int) sur l'id dans l'URL — OWASP A03
                echo '<a href="article.php?id=' . (int)$article['id'] . '" class="btn">Lire la suite</a>';

                // suppression en POST + CSRF, plus de lien GET vulnérable — OWASP A01
                if (isLoggedIn() && $_SESSION['user_id'] == $article['user_id']) {
                    echo '<form method="POST" action="delete_article.php" style="display:inline;" onsubmit="return confirm(\'Êtes-vous sûr ?\')">'
                       . '<input type="hidden" name="id" value="' . (int)$article['id'] . '">'
                       . '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($csrf) . '">'
                       . '<button type="submit" class="btn danger">Supprimer</button>'
                       . '</form>';
                }
                echo '</div>';
            }
        } else {
            echo '<p>Aucun article trouvé.</p>';
        }
        ?>
    </div>
</body>
</html>
