<?php
// auth.php - Gestion de l'authentification
// FAILLES MULTIPLES : Injection SQL, contrôle de session faible

require 'config.php';

// FAILLE 3 : Injection SQL - Pas de prepared statement
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    
    if ($_POST['action'] === 'register') {
        $username = $_POST['username'];
        $email = $_POST['email'];
        $password = $_POST['password'];
        
        // FAILLE 4 : Password stocké sans hash - texte brut !
        $sql = "INSERT INTO users (username, email, password) 
                VALUES ('$username', '$email', '$password')";
        
        if ($conn->query($sql)) {
            $_SESSION['message'] = "Inscription réussie. Vous pouvez vous connecter.";
        } else {
            $_SESSION['error'] = $conn->error;
        }
    }
    
    if ($_POST['action'] === 'login') {
        $username = $_POST['username'];
        $password = $_POST['password'];
        
        // FAILLE 5 : Injection SQL dans la requête de login
        $sql = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
        $result = $conn->query($sql);
        
        if ($result && $result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            header("Location: index.php");
        } else {
            $_SESSION['error'] = "Identifiants incorrects";
        }
    }
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function logout() {
    session_destroy();
    header("Location: index.php");
}
?>
