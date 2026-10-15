# nettoyage-disque

Analyse ton dossier personnel, montre où va la place (treemap explorable) et propose ce qui peut partir : caches, builds régénérables (`node_modules`, `.next`, `target`, `.venv`), dossiers à trier à la main. Tu coches, tu confirmes, et les éléments vont **dans la Corbeille** (récupérables).

Un seul binaire pour macOS, Windows et Linux : il analyse le disque, ouvre une page dans ton navigateur (servie sur `127.0.0.1` uniquement) et s'arrête quand tu cliques sur « Quitter ».

## Installer

macOS et Linux :

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/DG-Elom/nettoyage-disque/releases/latest/download/nettoyage-disque-installer.sh | sh
```

Windows (PowerShell) :

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/DG-Elom/nettoyage-disque/releases/latest/download/nettoyage-disque-installer.ps1 | iex"
```

Puis lance `nettoyage-disque`.

Les archives des [Releases](https://github.com/DG-Elom/nettoyage-disque/releases) fonctionnent aussi. Sur macOS, un binaire téléchargé avec le navigateur est bloqué par Gatekeeper (il n'est pas signé) : `xattr -d com.apple.quarantine nettoyage-disque`. L'installeur `curl` n'a pas ce problème.

## Ce qui est proposé

| Classe | Exemples | Action |
| --- | --- | --- |
| Sans risque | caches d'applications, cache npm/pip/Bun, `target` Rust, `.next`, DerivedData Xcode, temporaires Windows | Corbeille |
| À examiner | `node_modules`, `.venv`, modèles Hugging Face, Gradle, Maven | Corbeille, décoché par défaut |
| Commande | `uv cache prune`, `brew cleanup`, `go clean -modcache` | Commande à copier, jamais exécutée |
| Personnel | Téléchargements, Vidéos, médias WhatsApp | Ouvert dans le gestionnaire de fichiers, jamais supprimé |

Seuls les éléments de plus de 20 Mo sont listés. Les règles sont dans [`src/rules.rs`](src/rules.rs).

## Sécurité

- Le serveur n'écoute que sur `127.0.0.1` et vérifie l'en-tête `Host`.
- Chaque lancement crée un jeton aléatoire, exigé sur toutes les requêtes `/api/*`.
- La page ne peut supprimer que les recommandations de l'analyse en cours, désignées par leur numéro : jamais un chemin envoyé par le navigateur.
- Rien n'est supprimé définitivement : vide la Corbeille toi-même.

## Options

```text
--no-browser   ne pas ouvrir le navigateur (l'adresse est affichée)
--port <n>     port local
--home <dir>   dossier à analyser
--json         analyser, afficher le JSON et quitter
```

## Construire

```sh
cargo build --release
```

Les binaires publiés sont construits par GitHub Actions avec [dist](https://github.com/axodotdev/cargo-dist) à chaque tag `v*`.
