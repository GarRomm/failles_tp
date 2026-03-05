<?php
// auth.php - Gestion de l'authentification
require 'config.php';

// token aléatoire généré une fois par session, stocké côté serveur
// OWASP A01 – CSRF
function generateCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// comparaison en temps constant pour éviter les timing attacks
function verifyCsrfToken(string $token): bool {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// max 5 tentatives par IP sur 5 min — anti brute force
// OWASP A07 – Identification and Authentication Failures
function checkRateLimit(string $key, int $maxAttempts = 5, int $windowSeconds = 300): bool {
    $now = time();
    if (!isset($_SESSION['rate_limit'][$key])) {
        $_SESSION['rate_limit'][$key] = ['count' => 0, 'start' => $now];
    }
    $rl = &$_SESSION['rate_limit'][$key];
    if ($now - $rl['start'] > $windowSeconds) {
        $rl = ['count' => 0, 'start' => $now];
    }
    $rl['count']++;
    return $rl['count'] <= $maxAttempts;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {

    // on vérifie le token CSRF sur tous les POST, sans exception
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = "Requête invalide (CSRF).";
        header("Location: index.php");
        exit;
    }

    if ($_POST['action'] === 'register') {
        $username = trim($_POST['username'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if (strlen($username) < 3 || strlen($password) < 8) {
            $_SESSION['error'] = "Nom d'utilisateur (3 car. min) et mot de passe (8 car. min) requis.";
            header("Location: register.php");
            exit;
        }

        // bcrypt hash le mdp avec un salt auto, jamais en clair
        // OWASP A02 – Cryptographic Failures
        $passwordHash = password_hash($password, PASSWORD_BCRYPT);

        // requête préparée : les données n'entrent jamais dans le SQL
        // OWASP A03 – Injection SQL
        $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param('sss', $username, $email, $passwordHash);

        if ($stmt->execute()) {
            $_SESSION['message'] = "Inscription réussie. Vous pouvez vous connecter.";
        } else {
            error_log("Erreur inscription : " . $stmt->error); // log serveur, rien pour l'user
            $_SESSION['error'] = "Une erreur est survenue lors de l'inscription.";
        }
        $stmt->close();
        header("Location: register.php");
        exit;
    }

    if ($_POST['action'] === 'login') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        // on bloque si trop de tentatives — OWASP A07
        if (!checkRateLimit('login_' . md5($_SERVER['REMOTE_ADDR']))) {
            $_SESSION['error'] = "Trop de tentatives. Réessayez dans quelques minutes.";
            header("Location: login.php");
            exit;
        }

        // OWASP A03 – requête préparée, on récupère juste le hash
        $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            // password_verify compare le mdp saisi avec le hash en BDD — OWASP A02
            if (password_verify($password, $user['password'])) {
                // nouvel ID de session après login pour éviter la fixation de session
                // OWASP A07 – Session Fixation
                session_regenerate_id(true);
                $_SESSION['user_id']  = $user['id'];
                $_SESSION['username'] = $user['username'];
                unset($_SESSION['rate_limit']['login_' . md5($_SERVER['REMOTE_ADDR'])]);
                header("Location: index.php");
                $stmt->close();
                exit;
            }
        }
        $stmt->close();
        // message volontairement vague : on ne dit pas si c'est le login ou le mdp qui est faux
        $_SESSION['error'] = "Identifiants incorrects.";
        header("Location: login.php");
        exit;
    }
}

// déconnexion en POST + CSRF, un simple lien GET c'est trop facile à exploiter
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout'])) {
    if (verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        session_destroy();
    }
    header("Location: index.php");
    exit;
}

function isLoggedIn(): bool {
    return isset($_SESSION['user_id']);
}
