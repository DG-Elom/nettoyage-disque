//! Nettoyage du disque : analyse le dossier personnel, sert une page sur 127.0.0.1
//! et place dans la Corbeille les éléments recommandés que l'utilisateur confirme.

mod rules;
mod scan;

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use rules::Action;

const PAGE: &str = include_str!("../assets/index.html");
const MAX_BODY: u64 = 64 * 1024;

const HELP: &str = "nettoyage-disque — analyse ton dossier personnel et libère de la place

Usage : nettoyage-disque [options]

  --no-browser   ne pas ouvrir le navigateur (l'adresse est affichée)
  --port <n>     port local (par défaut : choisi automatiquement)
  --home <dir>   dossier à analyser (par défaut : dossier personnel)
  --json         analyser, afficher le résultat en JSON et quitter
  -V, --version  version

Rien n'est supprimé sans confirmation dans la page ; tout passe par la Corbeille.";

struct App {
    home: PathBuf,
    scanning: bool,
    data: Option<Value>,
    targets: Vec<(PathBuf, Action)>,
    done: HashSet<usize>,
    progress: Arc<AtomicU64>,
}

struct Opts {
    home: Option<PathBuf>,
    port: u16,
    browser: bool,
    json: bool,
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts { home: None, port: 0, browser: true, json: false };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--home" => o.home = Some(it.next().ok_or("--home attend un dossier")?.into()),
            "--port" => o.port = it.next().and_then(|p| p.parse().ok()).ok_or("--port attend un nombre")?,
            "--no-browser" => o.browser = false,
            "--json" => o.json = true,
            "-V" | "--version" => {
                println!("nettoyage-disque {}", env!("CARGO_PKG_VERSION"));
                exit(0)
            }
            "-h" | "--help" => {
                println!("{HELP}");
                exit(0)
            }
            _ => return Err(format!("option inconnue : {a}")),
        }
    }
    Ok(o)
}

fn token() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("générateur aléatoire indisponible");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let opts = parse_args().unwrap_or_else(|e| {
        eprintln!("{e}\n\n{HELP}");
        exit(2)
    });
    let home = opts.home.clone().or_else(dirs::home_dir).unwrap_or_else(|| {
        eprintln!("Dossier personnel introuvable.");
        exit(1)
    });
    if !home.is_dir() {
        eprintln!("{} n'est pas un dossier.", home.display());
        exit(1)
    }
    let progress = Arc::new(AtomicU64::new(0));

    if opts.json {
        println!("{}", scan::scan(&home, &progress).data);
        return;
    }

    let listener = TcpListener::bind(("127.0.0.1", opts.port)).unwrap_or_else(|e| {
        eprintln!("Impossible d'ouvrir le port local : {e}");
        exit(1)
    });
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(opts.port);
    let server = Server::from_listener(listener, None).unwrap_or_else(|e| {
        eprintln!("Serveur local indisponible : {e}");
        exit(1)
    });
    let token = token();
    let url = format!("http://127.0.0.1:{port}/?t={token}");

    let app = Arc::new(Mutex::new(App {
        home: home.clone(),
        scanning: false,
        data: None,
        targets: Vec::new(),
        done: HashSet::new(),
        progress,
    }));
    start_scan(&app);

    println!("Nettoyage du disque — analyse de {}", home.display());
    println!("Page : {url}");
    println!("Ferme cette fenêtre (ou « Quitter » dans la page) pour arrêter.");
    if opts.browser {
        if let Err(e) = open::that(&url) {
            eprintln!("Navigateur non ouvert ({e}) : ouvre l'adresse ci-dessus.");
        }
    }

    for req in server.incoming_requests() {
        if handle(req, &app, &token, port) {
            break;
        }
    }
}

fn start_scan(app: &Arc<Mutex<App>>) {
    let (home, progress) = {
        let mut a = app.lock().unwrap();
        if a.scanning {
            return;
        }
        a.scanning = true;
        a.progress.store(0, Ordering::Relaxed);
        (a.home.clone(), a.progress.clone())
    };
    let app = app.clone();
    thread::spawn(move || {
        let r = scan::scan(&home, &progress);
        let mut a = app.lock().unwrap();
        a.data = Some(r.data);
        a.targets = r.targets;
        a.done.clear();
        a.scanning = false;
    });
}

fn header(req: &Request, name: &'static str) -> Option<String> {
    req.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str().to_string())
}

fn send(req: Request, code: u16, ctype: &str, body: String) {
    let mut resp = Response::from_string(body)
        .with_status_code(code)
        .with_header(Header::from_bytes("Content-Type", ctype).unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap());
    if ctype.starts_with("text/html") {
        let csp = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'";
        resp = resp.with_header(Header::from_bytes("Content-Security-Policy", csp).unwrap());
    }
    let _ = req.respond(resp);
}

/// Renvoie `true` quand l'utilisateur demande à quitter.
fn handle(mut req: Request, app: &Arc<Mutex<App>>, token: &str, port: u16) -> bool {
    // Contre le DNS rebinding : seule l'adresse locale exacte est servie.
    let host = header(&req, "Host").unwrap_or_default();
    if host != format!("127.0.0.1:{port}") && host != format!("localhost:{port}") {
        send(req, 403, "text/plain; charset=utf-8", "Hôte refusé".into());
        return false;
    }
    let path = req.url().split('?').next().unwrap_or("").to_string();
    let method = req.method().clone();
    if method == Method::Get && path == "/" {
        send(req, 200, "text/html; charset=utf-8", PAGE.into());
        return false;
    }
    // Jeton aléatoire par lancement, dans un en-tête : une autre page web ne peut ni le lire ni l'envoyer.
    if !path.starts_with("/api/") || header(&req, "X-Token").as_deref() != Some(token) {
        send(req, 403, "application/json", json!({"error": "accès refusé"}).to_string());
        return false;
    }
    let mut body = Value::Null;
    if method == Method::Post {
        let mut s = String::new();
        if req.as_reader().take(MAX_BODY).read_to_string(&mut s).is_ok() {
            body = serde_json::from_str(&s).unwrap_or(Value::Null);
        }
    }
    let (code, out, quit) = match (&method, path.as_str()) {
        (Method::Get, "/api/data") => (200, data(app), false),
        (Method::Post, "/api/trash") => trash_ids(app, &body),
        (Method::Post, "/api/open") => open_id(app, &body),
        (Method::Post, "/api/rescan") => {
            start_scan(app);
            (200, json!({"ok": true}), false)
        }
        (Method::Post, "/api/quit") => (200, json!({"ok": true}), true),
        _ => (404, json!({"error": "introuvable"}), false),
    };
    send(req, code, "application/json", out.to_string());
    quit
}

fn data(app: &Arc<Mutex<App>>) -> Value {
    let a = app.lock().unwrap();
    match (&a.data, a.scanning) {
        (Some(d), false) => {
            let done: Vec<String> = a.done.iter().map(|i| format!("r{i}")).collect();
            json!({"scanning": false, "done": done, "data": d})
        }
        _ => json!({"scanning": true, "dirs": a.progress.load(Ordering::Relaxed)}),
    }
}

/// Résout `r<i>` dans les recommandations de l'analyse en cours ; jamais un chemin venu de la requête.
fn resolve(a: &App, id: &str) -> Option<(usize, PathBuf, Action)> {
    let i: usize = id.strip_prefix('r')?.parse().ok()?;
    a.targets.get(i).map(|(p, act)| (i, p.clone(), *act))
}

fn trash_ids(app: &Arc<Mutex<App>>, body: &Value) -> (u16, Value, bool) {
    let Some(ids) = body.get("ids").and_then(Value::as_array) else {
        return (400, json!({"error": "liste « ids » attendue"}), false);
    };
    let mut jobs = Vec::new();
    {
        let a = app.lock().unwrap();
        if a.scanning {
            return (409, json!({"error": "analyse en cours"}), false);
        }
        for v in ids {
            let id = v.as_str().unwrap_or("");
            match resolve(&a, id) {
                Some((i, p, act @ (Action::Trash | Action::Empty))) => jobs.push((id.to_string(), i, p, act)),
                _ => return (400, json!({"error": format!("élément inconnu ou non supprimable : {id}")}), false),
            }
        }
    }
    let mut results = Vec::new();
    for (id, i, p, act) in jobs {
        let r = if !p.exists() {
            Ok("déjà absent".to_string())
        } else if act == Action::Empty {
            empty(&p)
        } else {
            trash::delete(&p).map(|_| String::new()).map_err(|e| e.to_string())
        };
        if r.is_ok() {
            app.lock().unwrap().done.insert(i);
        }
        let (ok, msg) = match r {
            Ok(m) => (true, m),
            Err(m) => (false, m),
        };
        results.push(json!({"id": id, "ok": ok, "msg": msg}));
    }
    (200, json!({"results": results}), false)
}

fn empty(dir: &Path) -> Result<String, String> {
    let (mut ok, mut skipped) = (0, 0);
    for e in fs::read_dir(dir).map_err(|e| e.to_string())?.flatten() {
        if trash::delete(e.path()).is_ok() {
            ok += 1
        } else {
            skipped += 1
        }
    }
    Ok(if skipped > 0 {
        format!("{ok} éléments, {skipped} ignorés (en cours d'utilisation)")
    } else {
        format!("{ok} éléments")
    })
}

fn open_id(app: &Arc<Mutex<App>>, body: &Value) -> (u16, Value, bool) {
    let id = body.get("id").and_then(Value::as_str).unwrap_or("");
    let Some((_, p, _)) = resolve(&app.lock().unwrap(), id) else {
        return (400, json!({"error": format!("élément inconnu : {id}")}), false);
    };
    match open::that(&p) {
        Ok(()) => (200, json!({"ok": true}), false),
        Err(e) => (500, json!({"error": e.to_string()}), false),
    }
}
