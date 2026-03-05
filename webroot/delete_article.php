<?php
// delete_article.php - Suppression d'un article
require 'auth.php';

if (!isLoggedIn() || !isset($_GET['id'])) {
    header("Location: index.php");
    exit;
}

$article_id = $_GET['id'];

// FAILLE 18 : Injection SQL
$sql = "SELECT * FROM articles WHERE id = " . $article_id;
$result = $conn->query($sql);

if (!$result || $result->num_rows === 0) {
    header("Location: index.php");
    exit;
}

$article = $result->fetch_assoc();

// Vérifier que l'utilisateur est bien le propriétaire
if ($article['user_id'] != $_SESSION['user_id']) {
    $_SESSION['error'] = "Vous n'avez pas la permission de supprimer cet article";
    header("Location: index.php");
    exit;
}

// FAILLE 19 : Injection SQL lors de la suppression - et PAS DE CSRF TOKEN
$sql = "DELETE FROM articles WHERE id = " . $article_id;

if ($conn->query($sql)) {
    $_SESSION['message'] = "Article supprimé avec succès";
} else {
    $_SESSION['error'] = "Erreur : " . $conn->error;
}

header("Location: index.php");
?>
