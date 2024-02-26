use std::collections::HashMap;
use std::sync::{RwLock, atomic::{AtomicUsize, Ordering}};

pub struct OidCounts {
    oids: RwLock<HashMap<String, AtomicUsize>>,
}

impl OidCounts {
    pub fn new() -> Self {
        OidCounts { oids: RwLock::new(HashMap::new()) }
    }

    pub fn increment(&self, oid: &str) {
        let mut oids = self.oids.write().unwrap();
        let counter = oids.entry(oid.to_string()).or_insert_with(|| AtomicUsize::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_count(&self, oid: &str) -> usize {
        let oids = self.oids.read().unwrap();
        if let Some(counter) = oids.get(oid) {
            counter.load(Ordering::SeqCst)
        } else {
            0
        }
    }

    pub fn oid_iter(&self) -> Vec<(String, usize)> {
        let oids = self.oids.read().unwrap();
        let mut result: Vec<(String, usize)> = oids.iter()
            .map(|(key, val)| (key.clone(), val.load(Ordering::SeqCst)))
            .collect();

        // Sort by descending count first, and lexicographically by OID as secondary sort.
        result.sort_unstable_by(|a, b| {
            // primary sort: descending counts
            let count_cmp = b.1.cmp(&a.1);
            if count_cmp == std::cmp::Ordering::Equal {
                // secondary sort: lexicographical OID comparison
                a.0.cmp(&b.0)
            } else {
                count_cmp
            }
        });

        result
    }

}
