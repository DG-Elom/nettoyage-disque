//! Parcours du dossier personnel : arbre pour la treemap et recommandations.
//! Lecture seule : ce module ne supprime rien.

use std::collections::{HashMap, HashSet};
use std::fs::{self, Metadata};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};

use crate::rules::{self, Action, Class};

const TREE_DEPTH: usize = 5;
const SIZE_DEPTH: usize = 8;
const MIN_NODE: u64 = 40 << 20;
const MIN_REC: u64 = 20 << 20;
const MAX_KIDS: usize = 28;
const MAX_DENIED: usize = 20;

#[derive(Serialize)]
pub struct Node {
    n: String,
    p: String,
    s: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    c: Vec<Node>,
    #[serde(skip_serializing_if = "is_false")]
    o: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

struct Found {
    path: PathBuf,
    title: String,
    class: Class,
    note: &'static str,
}

struct Ctx<'a> {
    home: &'a Path,
    dev: Option<u64>,
    skip: Vec<PathBuf>,
    sizes: Mutex<HashMap<PathBuf, u64>>,
    found: Mutex<Vec<Found>>,
    denied: Mutex<Vec<PathBuf>>,
    links: Mutex<HashSet<(u64, u64)>>,
    progress: &'a AtomicU64,
}

pub struct ScanResult {
    pub data: Value,
    /// Indexé comme les identifiants `r<i>` envoyés à la page.
    pub targets: Vec<(PathBuf, Action)>,
}

/// Taille occupée sur le disque (comme `du`), pas la taille apparente.
#[cfg(unix)]
fn alloc(m: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.blocks() * 512
}

#[cfg(windows)]
fn alloc(m: &Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;
    // Fichiers OneDrive « à la demande » : rien n'est stocké localement.
    const CLOUD_ONLY: u32 = 0x1000 | 0x40000 | 0x400000;
    if m.file_attributes() & CLOUD_ONLY != 0 {
        0
    } else {
        m.len()
    }
}

#[cfg(not(any(unix, windows)))]
fn alloc(m: &Metadata) -> u64 {
    m.len()
}

#[cfg(unix)]
fn dev(m: &Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(m.dev())
}

#[cfg(not(unix))]
fn dev(_: &Metadata) -> Option<u64> {
    None
}

/// Un fichier à plusieurs liens physiques n'est compté qu'une fois, comme `du`.
#[cfg(unix)]
fn first_link(ctx: &Ctx, m: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    m.nlink() < 2 || ctx.links.lock().unwrap().insert((m.dev(), m.ino()))
}

#[cfg(not(unix))]
fn first_link(_: &Ctx, _: &Metadata) -> bool {
    true
}

pub fn rel_path(home: &Path, rel: &str) -> PathBuf {
    let mut p = home.to_path_buf();
    p.extend(rel.split('/'));
    p
}

/// Chemin affiché : `~/a/b`, séparateur `/` sur tous les systèmes.
pub fn disp(home: &Path, p: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(r) if r.as_os_str().is_empty() => "~".into(),
        Ok(r) => {
            let parts: Vec<String> = r.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
            format!("~/{}", parts.join("/"))
        }
        Err(_) => p.display().to_string(),
    }
}

fn name_of(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Dossiers régénérables reconnus à leur forme ; enregistrés dans `ctx.found`.
fn detect(ctx: &Ctx, dir: &Path) -> bool {
    let Some(name) = dir.file_name().and_then(|n| n.to_str()) else { return false };
    let parent = dir.parent().unwrap_or(dir);
    let proj = name_of(parent);
    let hit = match name {
        "node_modules" if parent.join("package.json").is_file() => {
            Some((format!("node_modules — {proj}"), Class::Review, "Recréé par npm / pnpm / yarn install"))
        }
        ".next" if parent.join("package.json").is_file() => {
            Some((format!("Build Next.js — {proj}"), Class::Safe, "Régénéré par next build / next dev"))
        }
        "target" if parent.join("Cargo.toml").is_file() => {
            Some((format!("Build Rust — {proj}"), Class::Safe, "Régénéré par cargo build"))
        }
        ".venv" | "venv" if dir.join("pyvenv.cfg").is_file() => {
            Some((format!("Environnement Python — {proj}"), Class::Review, "Recréé par uv sync / pip install"))
        }
        _ => None,
    };
    match hit {
        Some((title, class, note)) => {
            ctx.found.lock().unwrap().push(Found { path: dir.to_path_buf(), title, class, note });
            true
        }
        None => false,
    }
}

fn entries(ctx: &Ctx, path: &Path) -> (u64, Vec<(PathBuf, u64)>) {
    let mut files = 0;
    let mut dirs = Vec::new();
    match fs::read_dir(path) {
        Err(e) => {
            if e.kind() == ErrorKind::PermissionDenied {
                ctx.denied.lock().unwrap().push(path.to_path_buf());
            }
        }
        Ok(rd) => {
            for entry in rd.flatten() {
                let Ok(m) = entry.metadata() else { continue };
                let ft = m.file_type();
                if ft.is_symlink() {
                    continue;
                }
                if !ft.is_dir() {
                    if first_link(ctx, &m) {
                        files += alloc(&m);
                    }
                    continue;
                }
                let p = entry.path();
                if (ctx.dev.is_some() && dev(&m) != ctx.dev) || ctx.skip.contains(&p) {
                    continue;
                }
                dirs.push((p, alloc(&m)));
            }
        }
    }
    (files, dirs)
}

fn walk(ctx: &Ctx, path: &Path, own: u64, depth: usize, in_match: bool) -> (u64, Option<Node>) {
    ctx.progress.fetch_add(1, Ordering::Relaxed);
    let in_match = in_match || detect(ctx, path);
    let (files, dirs) = entries(ctx, path);
    let mut total = own + files;
    let mut kids = Vec::new();
    for (p, s) in dirs {
        let (size, node) = walk(ctx, &p, s, depth + 1, in_match);
        total += size;
        kids.extend(node);
    }
    finish(ctx, path, total, depth, kids)
}

fn finish(ctx: &Ctx, path: &Path, total: u64, depth: usize, mut kids: Vec<Node>) -> (u64, Option<Node>) {
    if depth <= SIZE_DEPTH {
        ctx.sizes.lock().unwrap().insert(path.to_path_buf(), total);
    }
    if depth > TREE_DEPTH {
        return (total, None);
    }
    kids.retain(|k| k.s >= MIN_NODE);
    kids.sort_by_key(|k| std::cmp::Reverse(k.s));
    kids.truncate(MAX_KIDS);
    let p = disp(ctx.home, path);
    let rest = total.saturating_sub(kids.iter().map(|k| k.s).sum());
    if !kids.is_empty() && rest > MIN_NODE {
        kids.push(Node { n: "autres".into(), p: format!("{p}/…"), s: rest, c: vec![], o: true });
    }
    let n = if depth == 0 { "~".into() } else { name_of(path) };
    (total, Some(Node { n, p, s: total, c: kids, o: false }))
}

/// Taille d'un dossier hors de la carte déjà mesurée (plus profond que SIZE_DEPTH).
fn du(path: &Path) -> u64 {
    let Ok(rd) = fs::read_dir(path) else { return 0 };
    let mut total = 0;
    for e in rd.flatten() {
        let Ok(m) = e.metadata() else { continue };
        if m.file_type().is_symlink() {
            continue;
        }
        total += alloc(&m);
        if m.is_dir() {
            total += du(&e.path());
        }
    }
    total
}

struct Rec {
    path: PathBuf,
    title: String,
    class: Class,
    action: Action,
    note: &'static str,
    size: u64,
}

pub fn scan(home: &Path, progress: &AtomicU64) -> ScanResult {
    let root = fs::symlink_metadata(home).ok();
    let ctx = Ctx {
        home,
        dev: root.as_ref().and_then(dev),
        skip: rules::skip_walk().iter().map(|r| rel_path(home, r)).collect(),
        sizes: Mutex::new(HashMap::new()),
        found: Mutex::new(Vec::new()),
        denied: Mutex::new(Vec::new()),
        links: Mutex::new(HashSet::new()),
        progress,
    };

    // Un fil par dossier de premier niveau.
    let (files, top) = entries(&ctx, home);
    let c = &ctx;
    let parts: Vec<(u64, Option<Node>)> = std::thread::scope(|s| {
        let handles: Vec<_> = top.iter().map(|(p, own)| s.spawn(move || walk(c, p, *own, 1, false))).collect();
        handles.into_iter().map(|h| h.join().unwrap_or((0, None))).collect()
    });
    let total = root.as_ref().map(alloc).unwrap_or(0) + files + parts.iter().map(|p| p.0).sum::<u64>();
    let kids: Vec<Node> = parts.into_iter().filter_map(|p| p.1).collect();
    let tree = finish(&ctx, home, total, 0, kids).1;

    let sizes = ctx.sizes.into_inner().unwrap();
    let size_of = |p: &Path| sizes.get(p).copied().unwrap_or_else(|| du(p));
    let mut seen = HashSet::new();
    let mut recs: Vec<Rec> = Vec::new();
    let mut push = |recs: &mut Vec<Rec>, path: PathBuf, title: String, class, action, note| {
        if path.is_dir() && seen.insert(path.clone()) {
            let size = size_of(&path);
            recs.push(Rec { path, title, class, action, note, size });
        }
    };

    for r in rules::rules() {
        push(&mut recs, rel_path(home, r.rel), r.title.into(), r.class, r.action, r.note);
    }
    for (dir, title) in [(dirs::download_dir(), "Téléchargements"), (dirs::video_dir(), "Vidéos")] {
        if let Some(d) = dir.filter(|d| d.starts_with(home) && d != home) {
            push(&mut recs, d, title.into(), Class::Review, Action::Open, "Données personnelles : trier à la main");
        }
    }
    for ch in rules::children() {
        let Ok(rd) = fs::read_dir(rel_path(home, ch.rel)) else { continue };
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                let title = format!("{}{}", ch.prefix, e.file_name().to_string_lossy());
                push(&mut recs, e.path(), title, Class::Safe, Action::Trash, ch.note);
            }
        }
    }
    for f in ctx.found.into_inner().unwrap() {
        push(&mut recs, f.path, f.title, f.class, Action::Trash, f.note);
    }

    recs.retain(|r| r.size >= MIN_REC);
    // Un élément contenu dans un autre élément supprimable ferait doublon.
    let outer: Vec<PathBuf> = recs.iter().filter(|r| r.action != Action::Open).map(|r| r.path.clone()).collect();
    recs.retain(|r| !outer.iter().any(|o| o != &r.path && r.path.starts_with(o)));
    recs.sort_by(|a, b| (a.class != Class::Safe).cmp(&(b.class != Class::Safe)).then(b.size.cmp(&a.size)));

    let mut targets = Vec::new();
    let recs_json: Vec<Value> = recs
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let (a, cmd) = match r.action {
                Action::Trash => ("trash", None),
                Action::Empty => ("empty", None),
                Action::Open => ("open", None),
                Action::Cmd(c) => ("cmd", Some(c)),
            };
            let v = json!({
                "id": format!("r{i}"), "p": disp(home, &r.path), "t": r.title,
                "c": if r.class == Class::Safe { "safe" } else { "review" },
                "s": r.size, "note": r.note, "a": a, "cmd": cmd,
            });
            targets.push((r.path, r.action));
            v
        })
        .collect();

    let mut denied: Vec<String> = ctx.denied.into_inner().unwrap().iter().map(|p| disp(home, p)).collect();
    denied.sort();
    denied.dedup();
    let denied_count = denied.len();
    denied.truncate(MAX_DENIED);

    let excluded: Vec<Value> = rules::excluded()
        .iter()
        .filter(|(rel, _)| rel_path(home, rel).exists())
        .map(|(rel, note)| json!([format!("~/{rel}"), note]))
        .collect();
    let at = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);

    ScanResult {
        data: json!({
            "tree": tree, "recs": recs_json, "excluded": excluded,
            "denied": denied, "deniedCount": denied_count,
            "free": fs2::available_space(home).unwrap_or(0),
            "total": fs2::total_space(home).unwrap_or(0),
            "files": progress.load(Ordering::Relaxed), "at": at,
            "os": std::env::consts::OS,
        }),
        targets,
    }
}
