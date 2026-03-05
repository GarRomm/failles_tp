<?php
// article.php - Affichage d'un article avec commentaires
require 'auth.php';

if (!isset($_GET['id'])) {
    header("Location: index.php");
    exit;
}

// FAILLE 9 : Injection SQL - pas de prepared statement
$article_id = $_GET['id'];
$sql = "SELECT articles.*, users.username FROM articles 
        JOIN users ON articles.user_id = users.id 
        WHERE articles.id = " . $article_id;
$result = $conn->query($sql);

if (!$result || $result->num_rows === 0) {
    header("Location: index.php");
    exit;
}

$article = $result->fetch_assoc();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $article['title']; ?> - BlogSecure</title>
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
        textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; },
        button { padding: 10px 20px; background-color: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #218838; }
        .btn { display: inline-block; padding: 8px 15px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin-top: 10px; }
        .btn:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <header>
        <h1>BlogSecure</h1>
    </header>
    
    <nav>
        <a href="index.php">Accueil</a>
        <?php if (!isLoggedIn()): ?>
            <a href="login.php">Connexion</a>
        <?php else: ?>
            <a href="create_article.php">Nouvel Article</a>
            <a href="auth.php?logout=1">Déconnexion</a>
        <?php endif; ?>
    </nav>
    
    <div class="container">
        <div class="article-content">
            <!-- FAILLE 10 : XSS - Le titre n'est pas échappé -->
            <h1><?php echo $article['title']; ?></h1>
            <div class="meta">Par <?php echo $article['username']; ?> - <?php echo $article['created_at']; ?></div>
            
            <!-- FAILLE 11 : XSS - Le contenu n'est pas échappé -->
            <p><?php echo $article['content']; ?></p>
        </div>
        
        <div class="comments">
            <h2>Commentaires</h2>
            
            <?php
            // FAILLE 12 : Injection SQL dans la requête des commentaires
            $sql = "SELECT comments.*, users.username FROM comments 
                    JOIN users ON comments.user_id = users.id 
                    WHERE article_id = " . $article_id . " 
                    ORDER BY comments.created_at DESC";
            $result = $conn->query($sql);
            
            if ($result && $result->num_rows > 0) {
                while ($comment = $result->fetch_assoc()) {
                    echo '<div class="comment">';
                    echo '<div class="comment-author">' . $comment['username'] . '</div>';
                    echo '<div class="comment-date">' . $comment['created_at'] . '</div>';
                    // FAILLE 13 : XSS - Pas d'échappement du contenu du commentaire
                    echo '<div class="comment-text">' . $comment['comment'] . '</div>';
                    echo '</div>';
                }
            } else {
                echo '<p>Aucun commentaire pour le moment.</p>';
            }
            ?>
            
            <?php if (isLoggedIn()): ?>
            <h3>Ajouter un commentaire</h3>
            <!-- FAILLE 14 : Pas de protection CSRF -->
            <form method="POST" action="add_comment.php">
                <input type="hidden" name="article_id" value="<?php echo $article['id']; ?>">
                
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
