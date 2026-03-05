-- Structure de la base de données BlogSecure

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE articles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    article_id INT NOT NULL,
    user_id INT NOT NULL,
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Données de test
INSERT INTO users (username, email, password) VALUES
('admin', 'admin@blogsecure.com', 'password123'),
('user1', 'user1@blogsecure.com', 'password456'),
('user2', 'user2@blogsecure.com', 'password789');

INSERT INTO articles (user_id, title, content) VALUES
(1, 'Premier Article', 'Ceci est le contenu du premier article'),
(2, 'Deuxième Article', 'Ceci est le contenu du deuxième article'),
(1, 'Article sur la Sécurité', 'La sécurité est importante');

INSERT INTO comments (article_id, user_id, comment) VALUES
(1, 2, 'Très intéressant !'),
(1, 3, 'Merci pour ce contenu'),
(2, 1, 'Bon article');
