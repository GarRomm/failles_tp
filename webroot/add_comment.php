<?php
require 'auth.php';

if (!isLoggedIn() || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: index.php");
    exit;
}

// token CSRF obligatoire avant de toucher aux données — OWASP A01
if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
    $_SESSION['error'] = "Requête invalide (CSRF).";
    header("Location: index.php");
    exit;
}

// cast (int) sur les IDs : toute injection devient 0, pas de SQL — OWASP A03
$article_id = (int) ($_POST['article_id'] ?? 0);
$comment    = trim($_POST['comment'] ?? '');
$user_id    = (int) $_SESSION['user_id'];

// on refuse les données vides ou invalides
if ($article_id <= 0 || $comment === '') {
    $_SESSION['error'] = "Données invalides.";
    header("Location: index.php");
    exit;
}

// requête préparée — OWASP A03
$stmt = $conn->prepare("INSERT INTO comments (article_id, user_id, comment) VALUES (?, ?, ?)");
$stmt->bind_param('iis', $article_id, $user_id, $comment);

if ($stmt->execute()) {
    $_SESSION['message'] = "Commentaire ajouté avec succès.";
} else {
    error_log("Erreur commentaire : " . $stmt->error); // log serveur — OWASP A09
    $_SESSION['error'] = "Une erreur est survenue.";
}
$stmt->close();

header("Location: article.php?id=" . $article_id);
exit;
