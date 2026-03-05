<?php
// add_comment.php - Traitement de l'ajout de commentaire
require 'auth.php';

if (!isLoggedIn() || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: index.php");
    exit;
}

$article_id = $_POST['article_id'];
$comment = $_POST['comment'];
$user_id = $_SESSION['user_id'];

// FAILLE 15 : Injection SQL - pas de prepared statement
$sql = "INSERT INTO comments (article_id, user_id, comment) 
        VALUES ($article_id, $user_id, '$comment')";

if ($conn->query($sql)) {
    $_SESSION['message'] = "Commentaire ajouté avec succès";
} else {
    $_SESSION['error'] = "Erreur : " . $conn->error;
}

header("Location: article.php?id=" . $article_id);
?>
