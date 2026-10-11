//! rite-solver: opens the Annual Rite's sealed guestbook entries.
//!
//! Each entry is an RSW time-lock puzzle. Opening it means computing
//! b = 2^(2^T) mod N by squaring 2, T times, one after another. More
//! computers do not help; only a faster one does. Then
//! K = SHA-256(b, big-endian, left-padded to the byte length of N) and the
//! message is AES-256-GCM(K, iv) decrypted.
//!
//!   rite-solver open <entry-id>                  fetch from the site, square, decrypt
//!   rite-solver open <entry-id> --ledger 2026.json   read the entry from a ledger file
//!   rite-solver open --file entry.json           read the entry from a JSON file
//!   rite-solver bench [--seconds 20]             measure squarings/s and the T it implies
//!
//! Progress is checkpointed to disk (default ./rite-checkpoints) every
//! 30 seconds and on Ctrl-C; running the same command again resumes.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rug::integer::Order;
use rug::rand::RandState;
use rug::Integer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const DEFAULT_SITE: &str = "https://1010.b4ez.com";
const CHECKPOINT_EVERY: Duration = Duration::from_secs(30);
const SECONDS_PER_YEAR: f64 = 365.25 * 24.0 * 3600.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    year: Option<u32>,
    #[serde(default)]
    seal: Option<String>,
    /// optional public name, never sealed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    n_hex: String,
    #[serde(deserialize_with = "de_decimal")]
    t: String,
    iv_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Checkpoint {
    entry: Entry,
    /// squarings done so far, decimal
    done: String,
    /// 2^(2^done) mod N, hex
    x_hex: String,
    seconds_spent: f64,
}

/// T is a decimal string in the site's JSON (it can exceed 2^53), but accept a number too.
fn de_decimal<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    match Value::deserialize(d)? {
        Value::String(s) => Ok(s),
        Value::Number(n) => Ok(n.to_string()),
        other => Err(serde::de::Error::custom(format!("expected a decimal T, got {other}"))),
    }
}

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("rite-solver: {}", msg.as_ref());
    std::process::exit(1);
}

fn usage() -> ! {
    eprintln!(
        "uso:
  rite-solver open <entry-id> [--site URL] [--dir DIR] [--yes]
  rite-solver open <entry-id> --ledger ledger/YYYY.json [--dir DIR] [--yes]
  rite-solver open --file entry.json [--dir DIR] [--yes]
  rite-solver bench [--seconds N]"
    );
    std::process::exit(2);
}

struct Args {
    positional: Vec<String>,
    site: String,
    dir: PathBuf,
    file: Option<PathBuf>,
    ledger: Option<PathBuf>,
    seconds: f64,
    yes: bool,
    quiet: bool,
}

fn parse_args() -> (String, Args) {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_else(|| usage());
    let mut a = Args {
        positional: vec![],
        site: DEFAULT_SITE.to_string(),
        dir: PathBuf::from("rite-checkpoints"),
        file: None,
        ledger: None,
        seconds: 20.0,
        yes: false,
        quiet: false,
    };
    while let Some(arg) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--site" => a.site = val().trim_end_matches('/').to_string(),
            "--dir" => a.dir = PathBuf::from(val()),
            "--file" => a.file = Some(PathBuf::from(val())),
            "--ledger" => a.ledger = Some(PathBuf::from(val())),
            "--seconds" => a.seconds = val().parse().unwrap_or_else(|_| usage()),
            "--yes" | "-y" => a.yes = true,
            "--quiet" | "-q" => a.quiet = true,
            "-h" | "--help" => usage(),
            s if s.starts_with('-') => usage(),
            _ => a.positional.push(arg),
        }
    }
    (cmd, a)
}

fn main() {
    let (cmd, args) = parse_args();
    match cmd.as_str() {
        "open" => open(args),
        "bench" => bench(args.seconds),
        _ => usage(),
    }
}

// ---------------------------------------------------------------- loading

fn load_entry(args: &Args) -> Entry {
    if let Some(path) = &args.file {
        let text = fs::read_to_string(path).unwrap_or_else(|e| die(format!("{}: {e}", path.display())));
        return serde_json::from_str(&text).unwrap_or_else(|e| die(format!("{}: {e}", path.display())));
    }
    let id: u64 = args
        .positional
        .first()
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| die("el id del mensaje es un número"));
    if let Some(path) = &args.ledger {
        let text = fs::read_to_string(path).unwrap_or_else(|e| die(format!("{}: {e}", path.display())));
        let ledger: Value = serde_json::from_str(&text).unwrap_or_else(|e| die(format!("{}: {e}", path.display())));
        let found = ledger["guestbook"]
            .as_array()
            .and_then(|entries| entries.iter().find(|e| e["id"].as_u64() == Some(id)))
            .unwrap_or_else(|| die(format!("el mensaje {id} no está en {}", path.display())));
        return serde_json::from_value(found.clone()).unwrap_or_else(|e| die(format!("mensaje {id}: {e}")));
    }
    let url = format!("{}/api/guestbook/{id}", args.site);
    let body = ureq::get(&url)
        .call()
        .and_then(|mut r| r.body_mut().read_to_string())
        .unwrap_or_else(|e| die(format!("no se pudo descargar {url}: {e}")));
    serde_json::from_str(&body).unwrap_or_else(|e| die(format!("{url}: {e}")))
}

fn checkpoint_path(dir: &Path, entry: &Entry) -> PathBuf {
    let name = match entry.id {
        Some(id) => format!("entry-{id}.json"),
        None => {
            let h = Sha256::digest(entry.n_hex.as_bytes());
            format!("n-{}.json", h[..8].iter().map(|b| format!("{b:02x}")).collect::<String>())
        }
    };
    dir.join(name)
}

fn save_checkpoint(path: &Path, cp: &Checkpoint) {
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_string_pretty(cp).expect("checkpoint serializes");
    if let Err(e) = fs::write(&tmp, data).and_then(|_| fs::rename(&tmp, path)) {
        eprintln!("\nrite-solver: no se pudo guardar el avance en {}: {e}", path.display());
    }
}

// ---------------------------------------------------------------- squaring

/// Squarings per call to `square_times`, between checks for Ctrl-C and checkpoints.
const BATCH: u32 = 1 << 16;

/// x = x^(2^k) mod N: k squarings in a row. GMP's powm does them with
/// Montgomery reduction, about 15% faster than squaring and dividing each time,
/// so it is both how `open` squares and what `bench` measures.
fn square_times(x: &mut Integer, k: u32, n: &Integer) {
    let e = Integer::from(1) << k;
    x.pow_mod_mut(&e, n).expect("N is positive");
}

fn parse_hex(s: &str, what: &str) -> Integer {
    Integer::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap_or_else(|_| die(format!("{what} no es hexadecimal")))
}

/// SHA-256 of b, big-endian, left-padded to the byte length of N.
fn key_from_b(b: &Integer, n: &Integer) -> [u8; 32] {
    let len = (n.significant_bits() as usize).div_ceil(8);
    let digits = b.to_digits::<u8>(Order::Msf);
    let mut buf = vec![0u8; len - digits.len()];
    buf.extend_from_slice(&digits);
    Sha256::digest(&buf).into()
}

fn decrypt(entry: &Entry, b: &Integer, n: &Integer) -> Result<String, String> {
    let key = key_from_b(b, n);
    let iv = B64.decode(&entry.iv_b64).map_err(|e| format!("iv: {e}"))?;
    let nonce = Nonce::try_from(iv.as_slice()).map_err(|_| "el iv no tiene 12 bytes".to_string())?;
    let ct = B64.decode(&entry.ciphertext_b64).map_err(|e| format!("ciphertext: {e}"))?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let plain = cipher
        .decrypt(&nonce, ct.as_ref())
        .map_err(|_| "falló el descifrado: T o N equivocados, o el mensaje fue alterado".to_string())?;
    String::from_utf8(plain).map_err(|_| "el mensaje no está en UTF-8".into())
}

fn fmt_int(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push('.');
        }
        out.push(c);
    }
    out
}

fn fmt_duration(secs: f64) -> String {
    if !secs.is_finite() {
        return "∞".into();
    }
    let s = secs.max(0.0) as u64;
    let (y, rest) = (s / 31_557_600, s % 31_557_600);
    let (d, rest) = (rest / 86_400, rest % 86_400);
    let (h, rest) = (rest / 3_600, rest % 3_600);
    let (m, s) = (rest / 60, rest % 60);
    if y > 0 {
        format!("{y}a {d}d {h}h")
    } else if d > 0 {
        format!("{d}d {h}h {m}m")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

fn seal_name(seal: &str) -> &str {
    match seal {
        "y1" => "de 1 año",
        "y5" => "de 5 años",
        "y50" => "de 50 años",
        "y1000" => "de 1.000 años",
        other => other,
    }
}

fn slow_print(text: &str, quiet: bool) {
    if quiet {
        println!("{text}");
        return;
    }
    for line in text.lines() {
        println!("{line}");
        io::stdout().flush().ok();
        std::thread::sleep(Duration::from_millis(350));
    }
}

fn open(args: Args) {
    let entry = load_entry(&args);
    let n = parse_hex(&entry.n_hex, "N");
    let t = Integer::from_str_radix(&entry.t, 10).unwrap_or_else(|_| die("T no es un número decimal"));
    if t < 1 {
        die("T debe ser positivo");
    }
    fs::create_dir_all(&args.dir).unwrap_or_else(|e| die(format!("{}: {e}", args.dir.display())));
    let cp_path = checkpoint_path(&args.dir, &entry);

    let (mut done, mut x, mut spent) = match fs::read_to_string(&cp_path) {
        Ok(text) => {
            let cp: Checkpoint =
                serde_json::from_str(&text).unwrap_or_else(|e| die(format!("{}: {e}", cp_path.display())));
            if cp.entry.n_hex != entry.n_hex || cp.entry.t != entry.t {
                die(format!("{} pertenece a otro acertijo", cp_path.display()));
            }
            (
                Integer::from_str_radix(&cp.done, 10).unwrap_or_else(|_| die("avance guardado inválido")),
                parse_hex(&cp.x_hex, "checkpoint x"),
                cp.seconds_spent,
            )
        }
        Err(_) => (Integer::new(), Integer::from(2), 0.0),
    };

    let by = entry.name.as_deref().map(|n| format!(", firmado por {n}")).unwrap_or_default();
    let label = match (entry.id, entry.year, &entry.seal) {
        (Some(id), Some(y), Some(s)) => format!("el mensaje {id}{by}, sellado el Día de {y}, sello {}", seal_name(s)),
        (Some(id), _, _) => format!("el mensaje {id}"),
        _ => "un mensaje sin número".into(),
    };
    slow_print(
        &format!(
            "
    ◯  EL LIBRO DE VISITAS SELLADO  ◯

    Has elegido {label}.
    N tiene {} bits. T es {} cuadrados.
    Cada cuadrado espera al anterior.
    Ninguna multitud de máquinas puede ayudarte; solo la paciencia.
",
            n.significant_bits(),
            fmt_int(&entry.t)
        ),
        args.quiet,
    );
    if done > 0 {
        println!(
            "    Retomando: {} cuadrados ya hechos, en {}.\n",
            fmt_int(&done.to_string()),
            fmt_duration(spent)
        );
    }
    if !args.yes && done == 0 {
        print!("    Presiona Enter para empezar, o Ctrl-C para alejarte. ");
        io::stdout().flush().ok();
        let mut line = String::new();
        io::stdin().read_line(&mut line).ok();
    }

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst)).ok();
    }

    let t_f = t.to_f64();
    let started = Instant::now();
    let spent_before = spent;
    let done_at_start = done.to_f64();
    let mut last_save = Instant::now();
    let mut last_print = Instant::now() - Duration::from_secs(10);

    while done < t {
        let remaining = Integer::from(&t - &done);
        let steps = if remaining < BATCH { remaining.to_u32().unwrap() } else { BATCH };
        square_times(&mut x, steps, &n);
        done += steps;

        let now = Instant::now();
        let interrupted = stop.load(Ordering::SeqCst);
        if now - last_save >= CHECKPOINT_EVERY || interrupted || done == t {
            spent = spent_before + started.elapsed().as_secs_f64();
            save_checkpoint(
                &cp_path,
                &Checkpoint { entry: entry.clone(), done: done.to_string(), x_hex: x.to_string_radix(16), seconds_spent: spent },
            );
            last_save = now;
        }
        if !args.quiet && (now - last_print >= Duration::from_secs(1) || done == t) {
            let elapsed = started.elapsed().as_secs_f64().max(1e-9);
            let rate = (done.to_f64() - done_at_start) / elapsed;
            let eta = (t_f - done.to_f64()) / rate;
            print!(
                "\r    {} / {}  ({:.6}%)  {:.2}M cuadrados/s  faltan {}   ",
                fmt_int(&done.to_string()),
                fmt_int(&entry.t),
                100.0 * done.to_f64() / t_f,
                rate / 1e6,
                fmt_duration(eta)
            );
            io::stdout().flush().ok();
            last_print = now;
        }
        if interrupted && done < t {
            println!("\n\n    El cálculo descansa. El avance queda guardado en {}.", cp_path.display());
            println!("    Ejecuta el mismo comando otra vez para continuar.");
            std::process::exit(130);
        }
    }

    println!("\n");
    match decrypt(&entry, &x, &n) {
        Ok(message) => {
            slow_print("    El sello está roto. El mensaje dice:\n", args.quiet);
            println!("{message}");
        }
        Err(e) => die(e),
    }
}

// ---------------------------------------------------------------- bench

/// Measures 2048-bit modular squarings per second, the way `open` does them,
/// and prints the T each seal needs to last its target time on this machine.
fn bench(seconds: f64) {
    let mut rng = RandState::new();
    rng.seed(&Integer::from(1010));
    let mut n = Integer::from(Integer::random_bits(2048, &mut rng));
    n.set_bit(2047, true);
    n.set_bit(0, true);
    let mut x = Integer::from(2);

    println!("Elevando al cuadrado números de 2048 bits módulo N durante {seconds} s…");
    let started = Instant::now();
    let mut count: u64 = 0;
    while started.elapsed().as_secs_f64() < seconds {
        square_times(&mut x, BATCH, &n);
        count += u64::from(BATCH);
    }
    let rate = count as f64 / started.elapsed().as_secs_f64();
    println!("{:.0} cuadrados/s ({:.1} ns cada uno)", rate, 1e9 / rate);
    println!();
    for (seal, years) in [("y1", 1.0), ("y5", 5.0), ("y50", 50.0), ("y1000", 1000.0)] {
        let t = (rate * SECONDS_PER_YEAR * years).round();
        println!("{seal:10} {years:>5} y  T = {:.0}", t);
    }
    if let Some(cpu) = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("model name")).map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string()))
    {
        println!("\nCPU: {cpu}");
    }
}
