//! Redaction, applied on read.
//!
//! An `m.room.redaction` is an ordinary timeline event: it is sent through the
//! room actor, persisted, and federated like any other. What makes it a
//! redaction is what the read paths do with it — every client-facing view of a
//! timeline asks the store which accepted redactions target the events it is
//! about to return, decides whether each is *allowed* to apply, and prunes the
//! target's content per the room version's redaction rules, carrying the
//! redaction along as `unsigned.redacted_because`.
//!
//! Allowed means what the spec's apply-time check means: the redaction's
//! sender is the target's sender, or holds at least the room's `redact` power
//! level. A redaction that is not allowed is stored and served as an event,
//! and changes nothing — exactly what a real homeserver does with it.

use std::collections::BTreeMap;

use neutrino_event::{Event, RoomVersion, base_version};
use neutrino_store::{EventStore, StateStore, StorageError};
use ruma::events::{AnySyncTimelineEvent, AnyTimelineEvent};
use ruma::serde::Raw;
use ruma::{EventId, OwnedEventId, RoomId, UserId};
use serde_json::Value;

/// Spec default for the `redact` power level when the room's power levels
/// leave it unset.
const DEFAULT_REDACT_LEVEL: i64 = 50;

/// The redactions that apply to `events`, keyed by target id. At most one per
/// target — the earliest allowed one wins, which is stable across peers since
/// stream order on a mesh node is arrival order and the content is the same
/// whichever redaction pruned it.
pub(crate) async fn applicable<S: EventStore + StateStore>(
    store: &S,
    room_id: &RoomId,
    events: &[Event],
) -> Result<BTreeMap<OwnedEventId, Event>, StorageError> {
    let ids: Vec<&EventId> = events.iter().map(|e| &*e.event_id).collect();
    let redactions = store.redactions_of(room_id, &ids).await?;
    if redactions.is_empty() {
        return Ok(BTreeMap::new());
    }
    let by_id: BTreeMap<&EventId, &Event> = events.iter().map(|e| (&*e.event_id, e)).collect();
    let levels = power_levels(store, room_id).await?;

    let mut out = BTreeMap::new();
    for redaction in redactions {
        let Some(target_id) = redacts(&redaction) else {
            continue;
        };
        let Some(target) = by_id.get(&*target_id) else {
            continue;
        };
        if out.contains_key(&target_id) {
            continue;
        }
        let same_sender = redaction.sender == target.sender;
        if same_sender || levels.user_level(&redaction.sender) >= levels.redact {
            out.insert(target_id, redaction);
        }
    }
    Ok(out)
}

/// The `/sync` timeline view of `events`, redacted where a redaction applies.
pub(crate) fn sync_views(
    events: &[Event],
    applicable: &BTreeMap<OwnedEventId, Event>,
) -> Vec<Raw<AnySyncTimelineEvent>> {
    let version = rules();
    events
        .iter()
        .map(|e| {
            neutrino_event::event_view::sync_timeline_view(e, applicable.get(&e.event_id), version)
        })
        .collect()
}

/// The `/messages` view of `events`, redacted where a redaction applies.
pub(crate) fn timeline_views(
    events: &[Event],
    applicable: &BTreeMap<OwnedEventId, Event>,
) -> Vec<Raw<AnyTimelineEvent>> {
    let version = rules();
    events
        .iter()
        .map(|e| neutrino_event::event_view::timeline_view(e, applicable.get(&e.event_id), version))
        .collect()
}

/// The redaction rules to prune with. This server speaks one room version,
/// whose keep-list is the base version's; a second version would make this a
/// lookup against the room.
fn rules() -> &'static RoomVersion {
    base_version()
}

/// `content.redacts` of a redaction event (room v11+ carries it in content).
fn redacts(redaction: &Event) -> Option<OwnedEventId> {
    let content: Value = serde_json::from_str(redaction.content.get()).ok()?;
    let id = content.get("redacts")?.as_str()?;
    OwnedEventId::try_from(id).ok()
}

/// What the room's `m.room.power_levels` says about who may redact.
struct Levels {
    users: BTreeMap<String, i64>,
    users_default: i64,
    redact: i64,
}

impl Levels {
    fn user_level(&self, user: &UserId) -> i64 {
        self.users
            .get(user.as_str())
            .copied()
            .unwrap_or(self.users_default)
    }
}

async fn power_levels<S: StateStore>(store: &S, room_id: &RoomId) -> Result<Levels, StorageError> {
    let event = store
        .current_state_event(room_id, "m.room.power_levels", "")
        .await?;
    let content: Value = event
        .and_then(|e| serde_json::from_str(e.content.get()).ok())
        .unwrap_or(Value::Null);
    let as_i64 = |v: Option<&Value>| v.and_then(Value::as_i64);
    let users = content
        .get("users")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(u, l)| l.as_i64().map(|l| (u.clone(), l)))
                .collect()
        })
        .unwrap_or_default();
    Ok(Levels {
        users,
        users_default: as_i64(content.get("users_default")).unwrap_or(0),
        redact: as_i64(content.get("redact")).unwrap_or(DEFAULT_REDACT_LEVEL),
    })
}
