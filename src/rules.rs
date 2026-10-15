//! Table des règles par système : chemins relatifs au dossier personnel.

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Safe,
    Review,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Le dossier entier part à la Corbeille.
    Trash,
    /// Son contenu part à la Corbeille, le dossier reste (les fichiers verrouillés sont ignorés).
    Empty,
    /// Données personnelles : ouvert dans le gestionnaire de fichiers, jamais supprimé.
    Open,
    /// Commande à copier ; l'app ne l'exécute pas.
    Cmd(&'static str),
}

pub struct Rule {
    pub rel: &'static str,
    pub title: &'static str,
    pub class: Class,
    pub action: Action,
    pub note: &'static str,
}

/// Chaque sous-dossier devient une recommandation « sans risque ».
pub struct Children {
    pub rel: &'static str,
    pub prefix: &'static str,
    pub note: &'static str,
}

use Action::*;
use Class::*;

const fn r(rel: &'static str, title: &'static str, class: Class, action: Action, note: &'static str) -> Rule {
    Rule { rel, title, class, action, note }
}

const COMMON: &[Rule] = &[
    r(".npm/_cacache", "Cache npm", Safe, Trash, "Re-téléchargé à la demande"),
    r(".cargo/registry/cache", "Archives des crates Cargo", Safe, Trash, "Re-téléchargées au prochain build"),
    r(".bun/install/cache", "Cache Bun", Safe, Trash, "Re-téléchargé à la demande"),
    r(".cache/pre-commit", "Environnements pre-commit", Safe, Trash, "Recréés au prochain commit"),
    r(".cache/uv", "Cache uv (Python)", Review, Cmd("uv cache prune"), "Peut héberger des environnements en service : « prune » ne retire que l'inutilisé"),
    r(".cache/huggingface", "Modèles Hugging Face", Review, Trash, "Re-téléchargement long si un outil les utilise"),
    r(".gradle/caches", "Cache Gradle", Review, Trash, "Re-téléchargé au prochain build Java / Android"),
    r(".m2/repository", "Dépôt Maven local", Review, Trash, "Re-téléchargé au prochain build Java"),
    r(".nuget/packages", "Paquets NuGet", Review, Cmd("dotnet nuget locals all --clear"), "Re-téléchargés au prochain build .NET"),
    r("go/pkg/mod", "Modules Go", Review, Cmd("go clean -modcache"), "Fichiers en lecture seule : passer par go clean"),
    r("Downloads", "Téléchargements", Review, Open, "Données personnelles : trier à la main"),
];

#[cfg(target_os = "macos")]
const OS: &[Rule] = &[
    r("Library/Caches/Homebrew", "Cache Homebrew", Safe, Cmd("brew cleanup --prune=all"), "Anciennes versions et téléchargements"),
    r("Library/Developer/Xcode/DerivedData", "Builds Xcode (DerivedData)", Safe, Trash, "Régénérés à la compilation"),
    r("Library/Logs", "Journaux d'applications", Safe, Empty, "Recréés au besoin"),
    r("Library/Developer/Xcode/iOS DeviceSupport", "Symboles d'appareils iOS", Review, Trash, "Recréés au branchement d'un iPhone"),
    r("Library/Developer/CoreSimulator/Devices", "Simulateurs iOS", Review, Cmd("xcrun simctl delete unavailable"), "Retire les simulateurs des anciennes versions"),
    r("Library/Application Support/Claude/vm_bundles", "Machine virtuelle de Claude Desktop", Review, Trash, "Re-téléchargée au prochain usage"),
    r("Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Message/Media", "Médias WhatsApp", Review, Open, "Nettoyer depuis WhatsApp › Réglages › Stockage, jamais à la main"),
    r("Movies", "Vidéos", Review, Open, "Données personnelles : trier à la main"),
];

#[cfg(target_os = "windows")]
const OS: &[Rule] = &[
    r("AppData/Local/Temp", "Fichiers temporaires", Safe, Empty, "Les fichiers en cours d'utilisation sont ignorés"),
    r("AppData/Local/npm-cache", "Cache npm", Safe, Trash, "Re-téléchargé à la demande"),
    r("AppData/Local/pip/Cache", "Cache pip", Safe, Trash, "Re-téléchargé à la demande"),
    r("AppData/Local/Yarn/Cache", "Cache Yarn", Safe, Trash, "Re-téléchargé à la demande"),
    r("AppData/Local/CrashDumps", "Rapports de plantage", Safe, Empty, "Utiles seulement pour un diagnostic"),
    r("AppData/Local/D3DSCache", "Cache de shaders DirectX", Safe, Empty, "Recréé par les jeux et applications 3D"),
    r("AppData/Local/NVIDIA/DXCache", "Cache de shaders NVIDIA", Safe, Empty, "Recréé par le pilote"),
    r("AppData/Local/Google/Chrome/User Data/Default/Cache", "Cache de Chrome", Safe, Empty, "Fermer Chrome avant"),
    r("AppData/Local/Microsoft/Edge/User Data/Default/Cache", "Cache d'Edge", Safe, Empty, "Fermer Edge avant"),
    r("AppData/Local/uv/cache", "Cache uv (Python)", Review, Cmd("uv cache prune"), "Peut héberger des environnements en service : « prune » ne retire que l'inutilisé"),
    r("Videos", "Vidéos", Review, Open, "Données personnelles : trier à la main"),
];

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const OS: &[Rule] = &[r("Videos", "Vidéos", Review, Open, "Données personnelles : trier à la main")];

pub fn rules() -> impl Iterator<Item = &'static Rule> {
    COMMON.iter().chain(OS.iter())
}

pub fn children() -> &'static [Children] {
    #[cfg(target_os = "macos")]
    return &[Children { rel: "Library/Caches", prefix: "Cache — ", note: "Fermer l'application avant ; recréé automatiquement" }];
    #[cfg(target_os = "windows")]
    return &[];
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    return &[Children { rel: ".cache", prefix: "Cache — ", note: "Fermer l'application avant ; recréé automatiquement" }];
}

/// Affiché dans « Exclu » ; jamais recommandé.
pub fn excluded() -> &'static [(&'static str, &'static str)] {
    #[cfg(target_os = "macos")]
    return &[
        ("Library/Mobile Documents", "iCloud Drive : libérer depuis le Finder (« Supprimer le téléchargement »)"),
        ("Library/CloudStorage", "Google Drive, OneDrive, Dropbox : gérés par leur application (non analysés)"),
    ];
    #[cfg(target_os = "windows")]
    return &[
        ("OneDrive", "Fichiers à la demande : libérer depuis l'Explorateur (« Libérer de l'espace »)"),
        ("AppData/Local/Packages", "Applications du Store : nettoyer depuis Paramètres › Applications"),
    ];
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    return &[(".local/share/Trash", "Corbeille : la vider depuis le gestionnaire de fichiers")];
}

/// Dossiers non parcourus (montages de fournisseurs cloud : les lister peut déclencher des téléchargements).
pub fn skip_walk() -> &'static [&'static str] {
    #[cfg(target_os = "macos")]
    return &["Library/CloudStorage"];
    #[cfg(not(target_os = "macos"))]
    return &[];
}
