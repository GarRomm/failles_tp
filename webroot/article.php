<?php
// article.php - Affichage d'un article avec ses commentaires
require 'auth.php';

if (!isset($_GET['id'])) {
    header("Location: index.php");
    exit;
}

// cast (int) : toute injection devient 0, pas de SQL qui passe — OWASP A03
$article_id = (int) $_GET['id'];

// requête préparée — OWASP A03 Injection SQL
$stmt = $conn->prepare(
    "SELECT articles.*, users.username FROM articles
     JOIN users ON articles.user_id = users.id
     WHERE articles.id = ?"
);
$stmt->bind_param('i', $article_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    $stmt->close();
    header("Location: index.php");
    exit;
}

$article = $result->fetch_assoc();
$stmt->close();

// token CSRF pour les formulaires de la page — OWASP A01
$csrf = generateCsrfToken();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- htmlspecialchars dans le title aussi — OWASP A03 XSS -->
    <title><?php echo htmlspecialchars($article['title'], ENT_QUOTES, 'UTF-8'); ?> - BlogSecure</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
        header { background-color: #333; color: white; padding: 20px; text-align: center; }
        nav { background-color: #444; padding: 10px; text-align: center; }
        nav a { color: white; margin: 0 15px; text-decoration: none; }
        nav a:hover { text-decoration: underline; }
        .container { max-width: 900px; margin: 20px auto; padding: 20px; }
        .article-content { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .article-content h1 { margin-bottom: 10px; color: #333; }
        .meta { color: #666; font-size: 0.9em; margin-bottom: 20px; }
        .article-content p { line-height: 1.8; margin-bottom: 15px; }
        .comments { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .comment { background: #f9f9f9; padding: 15px; margin: 15px 0; border-left: 4px solid #007bff; border-radius: 4px; }
        .comment-author { font-weight: bold; color: #333; }
        .comment-date { color: #999; font-size: 0.9em; }
        .comment-text { margin-top: 10px; line-height: 1.6; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 20px; background-color: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #218838; }
        .btn { display: inline-block; padding: 8px 15px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin-top: 10px; }
        .btn:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <header><h1>BlogSecure</h1></header>
    <nav>
        <a href="index.php">Accueil</a>
        <?php if (!isLoggedIn()): ?>
            <a href="login.php">Connexion</a>
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
        <div class="article-content">
            <!-- toutes les sorties passent par htmlspecialchars — OWASP A03 XSS -->
            <h1><?php echo htmlspecialchars($article['title'], ENT_QUOTES, 'UTF-8'); ?></h1>
            <div class="meta">
                Par <?php echo htmlspecialchars($article['username'], ENT_QUOTES, 'UTF-8'); ?>
                - <?php echo htmlspecialchars($article['created_at'], ENT_QUOTES, 'UTF-8'); ?>
            </div>
            <p><?php echo htmlspecialchars($article['content'], ENT_QUOTES, 'UTF-8'); ?></p>
        </div>

        <div class="comments">
            <h2>Commentaires</h2>
            <?php
            // requête préparée pour les commentaires — OWASP A03 Injection SQL
            $stmt2 = $conn->prepare(
                "SELECT comments.*, users.username FROM comments
                 JOIN users ON comments.user_id = users.id
                 WHERE article_id = ?
                 ORDER BY comments.created_at DESC"
            );
            $stmt2->bind_param('i', $article_id);
            $stmt2->execute();
            $comments = $stmt2->get_result();

            if ($comments->num_rows > 0) {
                while ($comment = $comments->fetch_assoc()) {
                    echo '<div class="comment">';
                    // htmlspecialchars sur chaque sortie — OWASP A03 XSS
                    echo '<div class="comment-author">' . htmlspecialchars($comment['username'], ENT_QUOTES, 'UTF-8') . '</div>';
                    echo '<div class="comment-date">'   . htmlspecialchars($comment['created_at'], ENT_QUOTES, 'UTF-8') . '</div>';
                    echo '<div class="comment-text">'   . htmlspecialchars($comment['comment'], ENT_QUOTES, 'UTF-8') . '</div>';
                    echo '</div>';
                }
            } else {
                echo '<p>Aucun commentaire pour le moment.</p>';
            }
            $stmt2->close();
            ?>

            <?php if (isLoggedIn()): ?>
            <h3>Ajouter un commentaire</h3>
            <!-- token CSRF injecté dans le form — OWASP A01 -->
            <form method="POST" action="add_comment.php">
                <!-- cast (int) sur l'id en sortie — OWASP A03 -->
                <input type="hidden" name="article_id" value="<?php echo (int)$article['id']; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf); ?>">
                <div class="form-group">
                    <label for="comment">Votre commentaire:</label>
                    <textarea id="comment" name="comment" rows="5" required></textarea>
                </div>
                <button type="submit">Publier le commentaire</button>
            </form>
            <?php else: ?>
            <p><a href="login.php">Connectez-vous</a> pour ajouter un commentaire.</p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
