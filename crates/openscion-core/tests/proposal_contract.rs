use openscion_core::initialize_repository;
use openscion_core::objects::{ObjectId, ObjectKind, ObjectStore, Proposal, Revision, ChangeErrorKind};
use std::fs;
use std::path::{Path,PathBuf};
use std::sync::atomic::{AtomicU64,Ordering};
use std::time::{SystemTime,UNIX_EPOCH};

static SEQUENCE:AtomicU64=AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new()->Self{
        let tick=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path=std::env::temp_dir().join(format!("openscion-proposal-{}-{}-{}",std::process::id(),tick,SEQUENCE.fetch_add(1,Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        initialize_repository(&path).unwrap();
        Self(path)
    }
    fn path(&self)->&Path{&self.0}
    fn store(&self)->ObjectStore{ObjectStore::open(&self.0).unwrap()}
    fn object_path(&self,id:&ObjectId)->PathBuf{
        let s=id.to_string();
        let (prefix,digest)=s.split_once('_').unwrap();
        self.0.join(".openscion/objects").join(prefix).join(&digest[..2]).join(digest)
    }
}
impl Drop for Fixture{fn drop(&mut self){fs::remove_dir_all(&self.0).ok();}}

#[test]
fn proposal_is_immutable_deterministic_and_never_creates_a_channel_head(){
    let f=Fixture::new();
    let store=f.store();
    let before=fs::read(f.path().join(".openscion/format")).unwrap();
    let empty=store.put_snapshot(&[]).unwrap();
    let proposal=Proposal::new(None,empty.clone(),"agent_01","Add a README").unwrap();
    let a=store.put_proposal(&proposal).unwrap();
    let b=store.put_proposal(&proposal).unwrap();
    assert_eq!(a,b);
    assert_eq!(a.kind(),ObjectKind::Proposal);
    assert_eq!(store.get_proposal(&a).unwrap(),proposal);
    assert_eq!(fs::read(f.path().join(".openscion/format")).unwrap(),before);
    assert!(!f.path().join(".openscion/channel").exists());
    assert!(!f.path().join(".openscion/main").exists());
}

#[test]
fn independent_proposals_from_one_base_both_exist(){
    let f=Fixture::new();
    let store=f.store();
    let base_snapshot=store.put_snapshot(&[]).unwrap();
    let root_proposal=store.put_proposal(&Proposal::new(None,base_snapshot.clone(),"agent_a","Root").unwrap()).unwrap();
    let root=store.create_revision(&root_proposal).unwrap();
    let alpha=store.put_proposal(&Proposal::new(Some(root.clone()),base_snapshot.clone(),"agent_a","Change A").unwrap()).unwrap();
    let beta=store.put_proposal(&Proposal::new(Some(root.clone()),base_snapshot.clone(),"agent_b","Change B").unwrap()).unwrap();
    assert_ne!(alpha,beta);
    assert_eq!(store.get_proposal(&alpha).unwrap().base(),Some(&root));
    assert_eq!(store.get_proposal(&beta).unwrap().base(),Some(&root));
    assert_eq!(store.ancestry(&root).unwrap(),vec![root]);
}

#[test]
fn revision_inherits_only_proposal_parent_and_snapshot(){
    let f=Fixture::new();
    let store=f.store();
    let snapshot=store.put_snapshot(&[]).unwrap();
    let p1=store.put_proposal(&Proposal::new(None,snapshot.clone(),"agent","Create root").unwrap()).unwrap();
    let first=store.create_revision(&p1).unwrap();
    let p2=store.put_proposal(&Proposal::new(Some(first.clone()),snapshot.clone(),"agent","Second change").unwrap()).unwrap();
    let second=store.create_revision(&p2).unwrap();
    let revision=store.get_revision(&second).unwrap();
    assert_eq!(revision.parent(),Some(&first));
    assert_eq!(revision.snapshot(),&snapshot);
    assert_eq!(revision.proposal(),&p2);
    assert_eq!(store.ancestry(&second).unwrap(),vec![second.clone(),first.clone()]);
    assert_eq!(store.create_revision(&p2).unwrap(),second);
}

#[test]
fn references_are_verified_before_publication(){
    let f=Fixture::new();
    let store=f.store();
    let missing_snapshot=ObjectId::for_content(ObjectKind::Snapshot,b"does-not-exist");
    let p=Proposal::new(None,missing_snapshot,"agent","Unsafe").unwrap();
    assert_eq!(store.put_proposal(&p).unwrap_err().kind,ChangeErrorKind::Missing);
    let valid=store.put_snapshot(&[]).unwrap();
    let missing_parent=ObjectId::for_content(ObjectKind::Revision,b"missing");
    let p=Proposal::new(Some(missing_parent),valid,"agent","Missing parent").unwrap();
    assert_eq!(store.put_proposal(&p).unwrap_err().kind,ChangeErrorKind::Missing);
}

#[test]
fn malformed_actor_and_intent_are_rejected(){
    let snapshot=ObjectId::for_content(ObjectKind::Snapshot,b"snapshot");
    for actor in ["","two words","../admin","admin/root","invalid:role"]{
        assert_eq!(
            Proposal::new(None,snapshot.clone(),actor,"safe").unwrap_err().kind,
            ChangeErrorKind::InvalidProposal
        );
    }
    let large_actor="a".repeat(81);
    assert!(Proposal::new(None,snapshot.clone(),&large_actor,"safe").is_err());
    for intent in ["","bad\0text","bad\rtext"]{
        assert_eq!(
            Proposal::new(None,snapshot.clone(),"agent",intent).unwrap_err().kind,
            ChangeErrorKind::InvalidProposal
        );
    }
    let large_intent="x".repeat(2049);
    assert!(Proposal::new(None,snapshot,"agent",&large_intent).is_err());
}

#[test]
fn wrong_type_and_truncated_encoding_are_rejected(){
    let snapshot=ObjectId::for_content(ObjectKind::Snapshot,b"s");
    let proposal=Proposal::new(None,snapshot,"agent","Intent").unwrap();
    let bytes=proposal.encode();
    assert_eq!(
        Proposal::decode(&bytes[..bytes.len()-1]).unwrap_err().kind,
        ChangeErrorKind::InvalidProposal
    );
    let mut bad_magic=bytes.clone();bad_magic[0]=0;
    assert_eq!(
        Proposal::decode(&bad_magic).unwrap_err().kind,
        ChangeErrorKind::InvalidProposal
    );
    let mut trailing=bytes;trailing.push(0);
    assert_eq!(
        Proposal::decode(&trailing).unwrap_err().kind,
        ChangeErrorKind::InvalidProposal
    );
    assert_ne!(
        ObjectId::for_content(ObjectKind::Proposal,b"same"),
        ObjectId::for_content(ObjectKind::Revision,b"same")
    );
}

#[test]
fn on_disk_proposal_corruption_is_detected_and_not_repaired(){
    let f=Fixture::new();
    let store=f.store();
    let snapshot=store.put_snapshot(&[]).unwrap();
    let payload=Proposal::new(None,snapshot,"agent","Intent").unwrap();
    let id=store.put_proposal(&payload).unwrap();
    let object=f.object_path(&id);
    fs::write(&object,b"tamper").unwrap();
    assert_eq!(store.get_proposal(&id).unwrap_err().kind,ChangeErrorKind::Corrupt);
    assert_eq!(store.put_proposal(&payload).unwrap_err().kind,ChangeErrorKind::Corrupt);
}

#[test]
fn corrupted_parent_prevents_ancestry_from_succeeding(){
    let f=Fixture::new();
    let store=f.store();
    let snapshot=store.put_snapshot(&[]).unwrap();
    let p1=store.put_proposal(&Proposal::new(None,snapshot.clone(),"a","Root").unwrap()).unwrap();
    let root=store.create_revision(&p1).unwrap();
    let p2=store.put_proposal(&Proposal::new(Some(root.clone()),snapshot,"b","Child").unwrap()).unwrap();
    let second=store.create_revision(&p2).unwrap();
    fs::write(f.object_path(&root),b"corrupt").unwrap();
    assert_eq!(store.ancestry(&second).unwrap_err().kind,ChangeErrorKind::Corrupt);
}

#[test]
fn revision_wire_format_rejects_unbound_or_extra_content(){
    let f=Fixture::new();
    let store=f.store();
    let snapshot=store.put_snapshot(&[]).unwrap();
    let proposal=store.put_proposal(&Proposal::new(None,snapshot,"agent","Root").unwrap()).unwrap();
    let revision=store.create_revision(&proposal).unwrap();
    let raw=fs::read(f.object_path(&revision)).unwrap();
    assert_eq!(Revision::decode(&raw).unwrap().proposal(),&proposal);
    let mut bad=raw.clone();bad.push(0);
    assert_eq!(Revision::decode(&bad).unwrap_err().kind,ChangeErrorKind::InvalidRevision);
    let mut bad_flag=raw;bad_flag[8]=2;
    assert_eq!(Revision::decode(&bad_flag).unwrap_err().kind,ChangeErrorKind::InvalidRevision);
}

#[test]
fn proposal_without_valid_store_is_refused(){
    let f=Fixture::new();
    let store=f.store();
    let snapshot=store.put_snapshot(&[]).unwrap();
    fs::write(f.path().join(".openscion/format"),b"bad").unwrap();
    let p=Proposal::new(None,snapshot,"agent","No store").unwrap();
    assert_eq!(store.put_proposal(&p).unwrap_err().kind,ChangeErrorKind::InvalidStore);
}


#[test]
fn invalid_grandparent_blocks_a_new_descendant_proposal() {
    let f = Fixture::new();
    let store = f.store();
    let snapshot = store.put_snapshot(&[]).unwrap();
    let root_proposal = store.put_proposal(
        &Proposal::new(None, snapshot.clone(), "root", "Start").unwrap()
    ).unwrap();
    let root = store.create_revision(&root_proposal).unwrap();
    let child_proposal = store.put_proposal(
        &Proposal::new(Some(root.clone()), snapshot.clone(), "child", "Continue").unwrap()
    ).unwrap();
    let child = store.create_revision(&child_proposal).unwrap();

    fs::write(f.object_path(&root), b"tampered ancestor").unwrap();
    assert_eq!(
        store.put_proposal(
            &Proposal::new(Some(child), snapshot, "agent", "Should fail").unwrap()
        ).unwrap_err().kind,
        ChangeErrorKind::Corrupt,
    );
}
