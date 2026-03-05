# TP Sécurité Web - Audit de Failles

## Objectifs
Identifier et documenter les failles de sécurité présentes dans une application web PHP. Vous devez analyser le code source et détecter les vulnérabilités suivantes :
- **XSS (Cross-Site Scripting)**
- **CSRF (Cross-Site Request Forgery)**
- **Injection SQL**

## Description du Projet
L'application "BlogSecure" est une plateforme de blog simple permettant aux utilisateurs de :
- S'inscrire et se connecter
- Créer, lire et supprimer des articles
- Publier des commentaires sur les articles

## Consignes

### Partie 1 : Analyse (40 points)
1. **Explorez le code source** de l'application et identifiez toutes les failles de sécurité
2. **Pour chaque faille trouvée**, documentez :
   - Le type de faille (XSS, CSRF, Injection SQL)
   - Le fichier et la ligne concernée
   - Une description détaillée de la vulnérabilité
   - L'impact potentiel sur la sécurité
   - Un scénario d'exploitation

### Partie 2 : Rapport d'Audit (40 points)
Créez un document (PDF ou HTML) contenant :
- Résumé exécutif (5-10 lignes)
- Liste de toutes les failles découvertes (minimum 4-5 failles)
- Pour chaque faille :
  - Code vulnérable (screenshot ou copie)
  - Explication technique
  - Risques et impacts
  - Recommandations de correction

### Partie 3 : Proposition de Corrections (20 points)
Pour au moins 3 failles, proposez :
- Le code correctif sécurisé
- Une explication des mesures de sécurité utilisées
- Les bonnes pratiques appliquées

## Durée
- **3-4 heures** pour une analyse approfondie

## Ressources autorisées
- Documentation OWASP Top 10
- Documentation PHP officielle
- Manuel des frameworks de sécurité

## Évaluation
- Complétude de l'analyse (avez-vous trouvé toutes les failles ?)
- Qualité de la documentation
- Précision des explications techniques
- Qualité des propositions de correction

## Livrables
1. Rapport d'audit détaillé
2. Code corrigé pour au moins 3 failles
3. Document résumant les points clés de sécurité appris

---

**Notes importantes :**
- Cette application est volontairement vulnérable à titre pédagogique
- N'utilisez JAMAIS les techniques d'exploitation en dehors d'un environnement de test
- Les failles présentes sont des exemples réels de vulnérabilités trouvées en production
