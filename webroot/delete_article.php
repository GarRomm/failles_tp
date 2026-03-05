<?php
require 'auth.php';

// suppression en POST uniquement, un lien GET c'est trop facile à déclencher à distance
// OWASP A01 – CSRF
if (!isLoggedIn() || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: index.php");
    exit;
}

// token CSRF obligatoire — OWASP A01
if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
    $_SESSION['error'] = "Requête invalide (CSRF).";
    header("Location: index.php");
    exit;
}

// cast (int) — OWASP A03
$article_id = (int) ($_POST['id'] ?? 0);

if ($article_id <= 0) {
    header("Location: index.php");
    exit;
}

// requête préparée — OWASP A03
$stmt = $conn->prepare("SELECT user_id FROM articles WHERE id = ?");
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

// on vérifie que c'est bien son article avant de supprimer — OWASP A01
if ($article['user_id'] != $_SESSION['user_id']) {
    $_SESSION['error'] = "Vous n'avez pas la permission de supprimer cet article.";
    header("Location: index.php");
    exit;
}

// double condition id + user_id : même si l'URL est bidouillée, ça ne supprime que le sien
$stmt = $conn->prepare("DELETE FROM articles WHERE id = ? AND user_id = ?");
$stmt->bind_param('ii', $article_id, $_SESSION['user_id']);

if ($stmt->execute()) {
    $_SESSION['message'] = "Article supprimé avec succès.";
} else {
    error_log("Erreur suppression : " . $stmt->error); // log serveur — OWASP A09
    $_SESSION['error'] = "Une erreur est survenue.";
}
$stmt->close();

header("Location: index.php");
exit;
?>
