use redb::{Database, Durability, ReadableTable, TableDefinition};
use std::{
    env,
    error::Error,
    fs,
    path::Path,
    sync::{Arc, Barrier},
    thread,
    time::Duration,
};

const HEAD: TableDefinition<&str, &str> = TableDefinition::new("heads");
const SEQ: TableDefinition<&str, u64> = TableDefinition::new("sequence");
const RECEIPT: TableDefinition<&str, &str> = TableDefinition::new("receipts");
const IDEM: TableDefinition<&str, &str> = TableDefinition::new("idempotency");

fn setup(db: &Database) {
    let mut tx = db.begin_write().unwrap();
    tx.set_durability(Durability::Immediate);
    {
        tx.open_table(HEAD).unwrap();
        tx.open_table(SEQ).unwrap();
        tx.open_table(RECEIPT).unwrap();
        tx.open_table(IDEM).unwrap();
    }
    tx.commit().unwrap();
}

fn barrier(phase: &str, requested: Option<&str>, marker: Option<&str>) {
    if requested != Some(phase) {
        return;
    }
    let path = marker.expect("fault marker required");
    fs::write(path, phase).unwrap();
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

// This is a database compatibility spike, not source-control authorization.
// The receipt strings are not signed or hashed and represent NO provenance.
fn promote(
    db: &Database,
    expected: &str,
    candidate: &str,
    key: &str,
    fingerprint: &str,
    fault: Option<&str>,
    marker: Option<&str>,
) -> Result<String, String> {
    let mut tx = db.begin_write().map_err(|e| e.to_string())?;
    tx.set_durability(Durability::Immediate);
    let idkey = format!("main/{key}");
    let previous = {
        let table = tx.open_table(IDEM).map_err(|e| e.to_string())?;
        table
            .get(idkey.as_str())
            .map_err(|e| e.to_string())?
            .map(|entry| entry.value().to_string())
    };
    if let Some(prior) = previous {
        if let Some((fp, receipt)) = prior.split_once('|') {
            if fp == fingerprint {
                return Ok(format!("IDEMPOTENT:{receipt}"));
            }
        }
        return Err("E_IDEMPOTENCY_CONFLICT".to_string());
    }
    let current_head = {
        let table = tx.open_table(HEAD).map_err(|e| e.to_string())?;
        table
            .get("main")
            .map_err(|e| e.to_string())?
            .map(|entry| entry.value().to_string())
            .unwrap_or_default()
    };
    if current_head != expected {
        return Err("E_HEAD_CONFLICT".to_string());
    }
    let current_seq = {
        let table = tx.open_table(SEQ).map_err(|e| e.to_string())?;
        table
            .get("main")
            .map_err(|e| e.to_string())?
            .map(|entry| entry.value())
            .unwrap_or(0)
    };
    let next = current_seq.checked_add(1).ok_or("sequence overflow")?;
    let receipt = format!("temporary-receipt:{next}:{candidate}");
    // Durable authority records must be updated in ONE write transaction.
    {
        tx.open_table(HEAD)
            .map_err(|e| e.to_string())?
            .insert("main", candidate)
            .map_err(|e| e.to_string())?;
        tx.open_table(SEQ)
            .map_err(|e| e.to_string())?
            .insert("main", next)
            .map_err(|e| e.to_string())?;
        let record_key = format!("main/{next:020}");
        tx.open_table(RECEIPT)
            .map_err(|e| e.to_string())?
            .insert(record_key.as_str(), receipt.as_str())
            .map_err(|e| e.to_string())?;
        let idemvalue = format!("{fingerprint}|{receipt}");
        tx.open_table(IDEM)
            .map_err(|e| e.to_string())?
            .insert(idkey.as_str(), idemvalue.as_str())
            .map_err(|e| e.to_string())?;
    }
    barrier("before-commit", fault, marker);
    tx.commit().map_err(|e| e.to_string())?;
    barrier("after-commit", fault, marker);
    Ok(format!("PROMOTED:{receipt}"))
}

fn state(db: &Database) -> String {
    let tx = db.begin_read().unwrap();
    let head = {
        let table = tx.open_table(HEAD).unwrap();
        table
            .get("main")
            .unwrap()
            .map(|x| x.value().to_string())
            .unwrap_or_default()
    };
    let seq = {
        let table = tx.open_table(SEQ).unwrap();
        table.get("main").unwrap().map(|x| x.value()).unwrap_or(0)
    };
    let receipts = tx.open_table(RECEIPT).unwrap().iter().unwrap().count();
    let idempotency = tx.open_table(IDEM).unwrap().iter().unwrap().count();
    format!("head={head};seq={seq};receipts={receipts};idempotency={idempotency}")
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        return Err("usage: init|promote|check|race <dbpath> [args]".into());
    }
    let dbpath = Path::new(&args[2]);
    let db = Arc::new(Database::create(dbpath)?);
    setup(&db);
    match args[1].as_str() {
        "init" => println!("{}", state(&db)),
        "check" => println!("{}", state(&db)),
        "promote" => {
            if args.len() < 7 {
                return Err("promote requires expected,candidate,key,fingerprint".into());
            }
            let fault = args.get(7).map(String::as_str);
            let marker = args.get(8).map(String::as_str);
            match promote(&db, &args[3], &args[4], &args[5], &args[6], fault, marker) {
                Ok(result) => println!("{result}"),
                Err(error) => {
                    println!("{error}");
                    std::process::exit(2)
                }
            }
            println!("{}", state(&db));
        }
        "race" => {
            let n: usize = args.get(3).ok_or("missing worker count")?.parse()?;
            let gate = Arc::new(Barrier::new(n));
            let mut handles = Vec::new();
            for i in 0..n {
                let db = Arc::clone(&db);
                let gate = Arc::clone(&gate);
                handles.push(thread::spawn(move || {
                    gate.wait();
                    promote(
                        &db,
                        "",
                        &format!("r1_{i}"),
                        &format!("key_{i}"),
                        &format!("fingerprint_{i}"),
                        None,
                        None,
                    )
                }));
            }
            let results: Vec<Result<String, String>> =
                handles.into_iter().map(|h| h.join().unwrap()).collect();
            let wins = results
                .iter()
                .filter(|r| r.as_ref().is_ok_and(|v| v.starts_with("PROMOTED:")))
                .count();
            let conflicts = results
                .iter()
                .filter(|r| matches!(r,Err(code) if code=="E_HEAD_CONFLICT"))
                .count();
            println!("race={n};wins={wins};head_conflicts={conflicts}");
            println!("{}", state(&db));
            if wins != 1 || conflicts != n - 1 {
                std::process::exit(3)
            }
        }
        _ => return Err("invalid command".into()),
    }
    Ok(())
}
