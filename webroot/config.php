<?php
// on lit les identifiants BDD depuis les variables d'env, pas en dur dans le code
// OWASP A05 – Security Misconfiguration
define('DB_HOST', getenv('DB_HOST') ?: '127.0.0.1');
define('DB_USER', getenv('DB_USER') ?: 'root');
define('DB_PASSWORD', getenv('DB_PASSWORD') ?: 'root');
define('DB_NAME', getenv('DB_NAME') ?: 'blogsecure');

$conn = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, 8889);

// si ça plante, on log côté serveur et on affiche rien de sensible à l'user
// OWASP A09 – Security Logging
if ($conn->connect_error) {
    error_log("Erreur de connexion BDD : " . $conn->connect_error);
    die("Une erreur interne est survenue. Veuillez réessayer plus tard.");
}

$conn->set_charset('utf8mb4');

session_start();
