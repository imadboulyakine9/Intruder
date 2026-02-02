# RAPPORT DE PROJET DE FIN D'ÉTUDES (PFE)
## INTRUDER: Automated Web Vulnerability Scanner & Orchestrator (Jarvis OS)
### "Orchestrating the Offensive Kill Chain"

---

**Membres de l'équipe :**
*   **Imad Boulyakine** (Lead Developer & System Architect)
*   **Zakaria Lahmouddi** (Security Analyst & Integrator)
*   **Youssef Tourabi** (Frontend Engineer & UX/UI)

**Année Universitaire :** 2025 - 2026
**Encadrant :** [Nom de l'encadrant]
**Établissement :** JobInTech - DataProtect


---

## TABLE DES MATIÈRES DÉTAILLÉE

1.  **Dédicaces et Remerciements**
2.  **Liste des Abréviations**
3.  **Chapitre 1 : Introduction Générale**
    *   1.1 Préambule
    *   1.2 La Cybersécurité à l'ère du Big Data
    *   1.3 Motivation du Projet
4.  **Chapitre 2 : Contexte et Étude de l'Art**
    *   2.1 Problématique : La Course contre la Montre
    *   2.2 Le Concept de "Vulnerability Management"
    *   2.3 Limites des Approches Traditionnelles
    *   2.4 Étude Comparative (Nessus, Acunetix, Open Source)
    *   2.5 La Philosophie "Orchestrateur" vs "Scanner Monolithique"
5.  **Chapitre 3 : Architecture et Conception**
    *   3.1 Architecture Micro-services
    *   3.2 Pipeline de Données : Le Pattern Producteur-Consommateur
    *   3.3 Stack Technologique (Justification des choix)
    *   3.4 Modélisation des Données (NoSQL)
    *   3.5 Diagramme de Séquence Global
6.  **Chapitre 4 : Implémentation Technique ("Under the Hood")**
    *   4.1 Le Cœur Asynchrone : Celery & Redis
    *   4.2 Module de Reconnaissance (The Eyes)
    *   4.3 Moteur d'Analyse Contextuelle (The Brain)
    *   4.4 Wrappers d'Outils et Parsing (The Hands)
    *   4.5 Interface Temps Réel et Websockets
7.  **Chapitre 5 : Analyse des Vulnérabilités & Mécanismes d'Attaque**
    *   5.1 Injection SQL (Théorie & Automatisation)
    *   5.2 Cross-Site Scripting (Reflected/Stored)
    *   5.3 Fuzzing et Découverte de Contenu
    *   5.4 Détection des Technologies et CBE
    *   5.5 Gestion des Faux Positifs et WAF Evasion
8.  **Chapitre 6 : Gestion de Projet et Méthodologie**
    *   6.1 Méthodologie Agile (Scrum)
    *   6.2 Outils de Collaboration
    *   6.3 Répartition des Tâches
9.  **Chapitre 7 : Résultats et Démonstration**
    *   7.1 Cas d'Usage : Audit d'une Cible Réelle (Autorisée)
    *   7.2 Performance et Métriques
10. **Conclusion Générale et Perspectives**
11. **Bibliographie**

---

# CHAPITRE 1 : INTRODUCTION GÉNÉRALE

### 1.1 Préambule
La sécurité informatique n'est plus une option de luxe, mais une nécessité absolue. Dans un monde hyper-connecté où les données sont le "nouvel or noir", la protection des applications web est devenue la priorité numéro un des entreprises. Cependant, la vitesse de développement des applications (DevOps, CI/CD) dépasse souvent la capacité des équipes de sécurité à les tester. C'est dans ce déséquilibre que naissent les failles de sécurité.

### 1.2 La Cybersécurité à l'ère du Big Data
Aujourd'hui, un auditeur de sécurité ne fait pas face à un serveur unique, mais à des infrastructures cloud complexes, éphémères et distribuées. La surface d'attaque est immense. Analyser manuellement chaque sous-domaine, chaque API, et chaque paramètre d'URL est devenu humainement impossible. L'automatisation n'est donc pas une simple aide au travail, c'est la seule réponse viable face à l'échelle des menaces modernes.

### 1.3 Motivation du Projet
Notre équipe, passionnée par le "Pentesting" (simulation d'attaques), a constaté un manque flagrant dans l'outillage open-source. On trouve d'excellents outils spécialisés (SQLMap pour les bases de données, Nmap pour le réseau), mais il manque un chef d'orchestre. Un outil capable de dire : "Tiens, j'ai trouvé un formulaire de login sur le port 8080, je devrais lancer Hydra", sans intervention humaine.

C'est ainsi qu'est né **INTRUDER (Projet Jarvis)**.

---

# CHAPITRE 2 : CONTEXTE ET ÉTUDE DE L'ART

### 2.1 Problématique : La Course contre la Montre
Le délai moyen entre la découverte d'une vulnérabilité critique (Zero-Day) et son exploitation massive par des robots malveillants se compte désormais en minutes. Les administrateurs systèmes doivent détecter leurs propres faiblesses avant les attaquants.
Le test d'intrusion (Pentest) traditionnel est :
1.  **Lent :** Une à deux semaines pour un audit complet.
2.  **Coûteux :** Nécessite des experts seniors.
3.  **Ponctuel :** Ne reflète la sécurité qu'à l'instant T.

### 2.2 Limites des Scanners Commerciaux
Des solutions comme Nessus ou Acunetix existent. Bien que puissantes, elles souffrent de défauts majeurs pour un contexte académique ou de startup :
*   **Boîte Noire :** Impossible de savoir exactement quel payload a été envoyé.
*   **Coût prohibitif :** Licences annuelles chères.
*   **Manque de fléxibilité :** Difficile d'ajouter un nouvel outil sorti la veille sur GitHub.

### 2.3 La Philosophie "Orchestrateur"
Notre approche se distingue par le concept d'orchestration. "JARVIS OS" n'est pas un scanner de vulnérabilité au sens strict (il ne réécrit pas les paquets TCP/IP lui-même). Il est une **couche d'abstraction intelligente** au-dessus des meilleurs outils du marché (Kali Linux Ecosystem).
Si la communauté Open Source sort un meilleur scanner XSS demain, Intruder peut l'intégrer en écrivant simplement un nouveau wrapper Python, sans refondre tout le système.

---

# CHAPITRE 3 : ARCHITECTURE ET CONCEPTION

### 3.1 Architecture Micro-services Modulaire
Pour garantir la robustesse et l'évolutivité, nous avons rejeté l'architecture monolithique classique au profit d'une architecture orientée événements.

**Les Composants Clés :**
1.  **Frontend (Client) :** Interface Web Reactiv (HTML5/Bootstrap/JS) qui communique uniquement via API et WebSockets.
2.  **API Gateway (Flask) :** Reçoit les ordres de scan, sert les rapports, et gère l'authentification.
3.  **Task Broker (Redis) :** Le "tuyau" dans lequel transitent les messages. Redis garantit la persistance en mémoire vive pour une latence minimale.
4.  **Workers (Celery) :** Les ouvriers. Ce sont des processus Python indépendants qui écoutent Redis. Ils exécutent les outils lourds (Nmap, Nuclei) de manière asynchrone.
5.  **Data Persistence (MongoDB) :** Stockage des résultats. Le format BSON (Binary JSON) de Mongo est parfait pour stocker les sorties JSON hétérogènes des outils de hacking.

### 3.2 Représentation Schématique du Flux de Données

```markdown
[Utilisateur] -> (Click "Scan") -> [Flask API]
                                      |
                                  (Push Task)
                                      v
                                  [Redis Queue]
                                      |
                                  (Pop Task)
                                      v
                              [Celery Worker Cluster]
                                /      |       \
                            [Nmap] [Subfinder] [Nuclei]...
                                \      |       /
                                 (Raw Output)
                                      v
                              [Parser & Normalizer]
                                      |
                                  (Structured Data) 
                                      v
                                 [MongoDB] <---- [Analyzer Engine]
```

### 3.3 Stack Technologique : Justification
*   **Python 3 :** Langage de prédilection de la cybersécurité (bibliothèques Scapy, Requests). Facilite l'interaction avec le système d'exploitation.
*   **Flask :** Framework micro-web léger. Contrairement à Django, il ne nous impose pas de structure rigide, ce qui est vital pour intégrer des outils système exotiques.
*   **Socket.IO :** Indispensable pour l'effet "Terminal en temps réel". L'utilisateur voit les logs du scanner défiler comme s'il était sur sa machine Kali.
*   **Cytoscape.js :** Bibliothèque de théorie des graphes pour visualiser la cartographie de l'attaque (Noeuds = Domaines/Vulnérabilités).

---

# CHAPITRE 4 : IMPLÉMENTATION TECHNIQUE

### 4.1 Le Cœur Asynchrone : Celery & Redis
L'un des défis majeurs a été la gestion des temps d'exécution. Un scan complet peut durer 4 heures. Une requête HTTP standard expire après 30 secondes.
**Solution :**
Nous utilisons le pattern "Fire and Forget".
1.  L'API génère un `UUID` unique pour le scan.
2.  Elle lance la tâche Celery et retourne immédiatement l'ID à l'utilisateur : `202 Experimental`.
3.  Le frontend s'abonne ensuite à un canal WebSocket nommé `room_<scan_id>`.
4.  Celery publie ses progrès ("Scanning port 80... 15%") dans ce canal.

Code (Simplifié) :
```python
@celery.task(bind=True)
def run_scan(self, target):
    process = subprocess.Popen(["nmap", target], stdout=PIPE)
    for line in process.stdout:
        socketio.emit('log', {'data': line}) # Streaming en temps réel
```

### 4.2 Module de Reconnaissance ("The Eyes") - `recon.py`
Ce module vise à maximiser la surface d'attaque connue.
*   **Technique Passive :** `Subfinder` interroge des sources publiques (VirusTotal, Censys) sans toucher la cible. C'est indétectable.
*   **Technique Active :** `Fuzzing` avec `FFuF`. On bombarde le serveur de requêtes pour trouver des dossiers cachés (`/admin`, `.git`, `backup.zip`).

**Innovation du projet :** Le filtrage intelligent.
Nous avons implémenté un système de "Pipe". La sortie de Subfinder (liste de 200 domaines) est nettoyée, puis passée à `HTTPX` pour ne garder que les domaines qui répondent (HTTP 200/301). Cela évite de scanner des domaines morts et fait gagner 80% du temps machine.

### 4.3 Moteur d'Analyse Contextuelle ("The Brain") - `analyzer.py`
C'est la valeur ajoutée intellectuelle du projet. Au lieu de lancer tous les outils aveuglément, nous avons codé une logique de décision.

Exemple de logique implémentée dans la classe `Analyzer` :
1.  **Entrée :** Données brutes de la reconnaissance.
2.  **Traitement :**
    *   Si `Wappalyzer` détecte "WordPress" -> Score +50 pour l'outil "WPScan".
    *   Si `httpx` trouve des URLs avec paramètres (`?id=1`) -> Score +90 pour "SQLMap".
    *   Si `Wafw00f` détecte "Cloudflare" -> Score -50 pour les outils bruyants (Nikto), activation du mode "Low Rate" pour Nuclei. et temper pour sqlmap
3.  **Sortie :** Une liste de recommandations d'attaques priorisées.

### 4.4 Wrappers & Parsing
Chaque outil externe (binaire Linux) possède son propre wrapper en Python (`scan_manager.py`).
Le rôle du wrapper est de :
1.  Construire la ligne de commande avec les arguments optimaux.
2.  Gérer les Timeouts (éviter qu'un processus ne pende indéfiniment).
3.  **Parser la sortie :** Convertir du XML (Nmap), du JSON (Nuclei) ou du texte brut  en un dictionnaire Python standardisé pour la base de données.

---

# CHAPITRE 5 : ANALYSE DES VULNÉRABILITÉS & MÉCANISMES

Dans ce chapitre, nous détaillons les catégories d'attaques automatisées par Intruder.

### 5.1 Injection SQL (SQLi)
**Théorie :** L'injection SQL survient quand une application insère des données utilisateur non fiables directement dans une requête base de données. Cela permet à l'attaquant de manipuler la requête pour exfiltrer des données.
**Automatisation via SQLMap :**
Notre intégration ne se contente pas de lancer `sqlmap -u URL`.
Elle :
*   Identifie automatiquement les formulaires.
*   Utilise des techniques d'évasion (Tamper Scripts) si un WAF est détecté.
*   Extrait la preuve de concept (le payload) pour le rapport, sans dumper toute la base de données (éthique).

### 5.2 Cross-Site Scripting (XSS)
**Théorie :** Injection de scripts malveillants dans des pages web vues par d'autres utilisateurs.
**Automatisation via Dalfox :**
Nous utilisons `Dalfox` pour sa rapidité et sa capacité à vérifier le DOM (Document Object Model). L'outil teste les réflexions de paramètres dans le code HTML. Si `<script>alert(1)</script>` est renvoyé tel quel par le serveur, la vulnérabilité est confirmée.

### 5.3 Vulnérabilités de Configuration & CVE (Nuclei)
Les scanners traditionnels cherchent des catégories. Nuclei cherche des **signatures**.
C'est une approche révolutionnaire basée sur des templates YAML.
Exemple de Template Nuclei intégré :
```yaml
id: git-config-exposure
info:
  name: Git Config Exposure
  severity: medium
requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"
```
Intruder met à jour ces templates quotidiennement, garantissant la détection des dernières CVE (Log4J, Spring4Shell).

### 5.4 WAF Evasion & Furtivité
Les pare-feux applicatifs (WAF) bloquent souvent les scanners.
Notre module `Analyzer` vérifie la présence d'un WAF au début du scan.
Si présent :
1.  Le scan passe en mode "Lent" (délais entre les requêtes).
2.  Les User-Agents sont randomisés à chaque requête.
3.  Des headers HTTP obfusqués sont utilisés.

---

# CHAPITRE 6 : GESTION DE PROJET

### 6.1 Méthodologie Agile
Nous avons adopté une méthode hybride inspirée de **Scrum**.
*   **Sprints :** Cycles de 1 semaine.
*   **Daily Stand-up :** Point rapide sur Whatsapp chaque soir.
*   **Backlog :** Gestion des tâches via un fichier `TODO.md` évolutif dans le repo, simulant un Kanban.

### 6.2 Outils de Collaboration
*   **Git & GitHub :** Gestion de versioning. Utilisation de branches (`feature/recon`, `fix/db-connection`) pour ne pas casser le code principal (Main).

### 6.3 Répartition des Tâches
* **Imad (Architecte & Lead Dev) :** Conception architecturale et développement complet (backend, workers, wrappers, CI/CD, déploiement).
* **Zakaria (Analyste Sécurité) :** Proposition et validation des choix d'outillage, sélection/configuration/tuning des scanners, campagnes de test et validation des résultats.
* **Youssef (QA) :** Conception du dashboard (visualisations), tests fonctionnels et UX, sessions de brainstorming et rédaction du rapport.

---

# CHAPITRE 7 : SCÉNARIO D'UTILISATION (WORKFLOW)

Pour valider le fonctionnement, voici le déroulé d'une session type sur la plateforme :

**Étape 1 : Initialisation**
L'opérateur se connecte au Dashboard. Il clique sur "New Target" et saisit le domaine : `testphp.vulnweb.com`.
Le système crée une entrée en base avec le statut `CREATED`.

**Étape 2 : Phase de Reconnaissance**
L'opérateur coche les modules désirés (Subfinder, Nmap, Wappalyzer) et lance le scan.
*   *Visuel :* Le terminal s'anime. "Subfinder started...".
*   *Backend :* Celery lance les processus.
*   *Résultat :* 2 minutes plus tard, les ports ouverts (80, 443, 3306) et les technos (PHP 5.6, Nginx) s'affichent sous forme de badges.

**Étape 3 : Phase d'Analyse (Automatique)**
L'utilisateur clique sur "Analyze". Le moteur `Analyzer.py` parcourt les résultats.
Il détecte que le site utilise PHP et possède des paramètres `artist=1`.
Il génère une carte (Card) : "SQLMap Recommended - Score 95%".

**Étape 4 : Phase d'Attaque (Exploitation)**
L'opérateur valide la suggestion SQLMap.
Intruder lance l'attaque. En arrière-plan, SQLMap teste les injections.
*   *Alerte :* Une notification apparaît "Critical Vulnerability Found: Boolean-based blind SQL Injection".

**Étape 5 : Reporting**
En fin de mission, un clic sur "Generate Report PDF".
Le module `report_generator.py` compile toutes les données, génère des graphiques statistiques, et produit un PDF professionnel liste les failles avec leur sévérité (CVSS) et les recommandations de correction.

---

# CHAPITRE 8 : CONCLUSION ET PERSPECTIVES

### Conclusion
Ce Projet a été un défi technique et organisationnel majeur. Il nous a permis de :
1.  **Maîtriser l'architecture Web complexe :** Asynchronisme, WebSockets, NoSQL.
2.  **Approfondir nos compétences offensives :** Comprendre comment fonctionnent réellement les outils de hacking au niveau du code.
3.  **Créer un produit viable :** Intruder n'est pas juste un prototype académique, c'est une base solide pour un outil de pentest réel.

Nous avons réussi à automatiser la chaîne complexe de la "Cyber Kill Chain", réduisant le temps de reconnaissance de plusieurs heures à quelques minutes.

### Perspectives d'Avenir
Le projet ouvre la porte à de nombreuses évolutions :
*   **Intelligence Artificielle (LLM) :** Intégrer un modèle comme GPT-4 ou Llama 3 pour analyser le code HTML et suggérer des vecteurs d'attaque encore plus subtils (Business Logic Errors).
*   **Mode "Sentinelle" (CRON) :** Programmer des scans récurrents chaque nuit pour détecter toute régression de sécurité (nouvelle CVE sur une librairie existante).
*   **Cloud Native :** Migrer l'architecture vers Kubernetes pour scaler les workers à l'infini et scanner des milliers de cibles simultanément.

**Jarvis OS** est la preuve que l'automatisation intelligente est l'avenir de la cybersécurité offensive.

---

# BIBLIOGRAPHIE & RÉFÉRENCES

1.  **OWASP Foundation.** (2023). *OWASP Top 10 web application security risks.*
3.  **Documentation Celery.** *Distributed Task Queue.* (https://docs.celeryq.dev)
4.  **Project Discovery.** *Nuclei & Subfinder Documentation.* (https://github.com/projectdiscovery)

---
*Fin du Rapport.*
