//! Controller connections share resource locks, never a lock around remote I/O
//! for every task. Reentrancy keeps internal status/checkpoint calls ordered.
use crate::error::{Error, Result};
use std::{
    collections::BTreeMap,
    sync::{Arc, Condvar, Mutex, Weak},
    thread::{self, ThreadId},
};

#[derive(Default)]
pub struct Coordination {
    locks: Mutex<BTreeMap<String, Weak<Resource>>>,
}
#[derive(Default)]
struct Resource {
    state: Mutex<State>,
    changed: Condvar,
}
#[derive(Default)]
struct State {
    owner: Option<ThreadId>,
    depth: usize,
}
pub struct Guard(Arc<Resource>);
fn unavailable<T>(_: T) -> Error {
    Error::new("Controller lock unavailable", "internal_error", 500)
}
impl Coordination {
    pub fn acquire(&self, name: String) -> Result<Guard> {
        let resource = {
            let mut locks = self.locks.lock().map_err(unavailable)?;
            if locks.len() > 256 {
                locks.retain(|_, value| value.strong_count() > 0);
            }
            if let Some(value) = locks.get(&name).and_then(Weak::upgrade) {
                value
            } else {
                let value = Arc::new(Resource::default());
                locks.insert(name, Arc::downgrade(&value));
                value
            }
        };
        let owner = thread::current().id();
        let mut state = resource.state.lock().map_err(unavailable)?;
        while state.owner.is_some_and(|current| current != owner) {
            state = resource.changed.wait(state).map_err(unavailable)?;
        }
        state.owner = Some(owner);
        state.depth += 1;
        drop(state);
        Ok(Guard(resource))
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        state.depth -= 1;
        if state.depth == 0 {
            state.owner = None;
            self.0.changed.notify_all();
        }
    }
}
