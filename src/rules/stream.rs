//! Borrowed detector candidates with locations in the complete physical line.
use super::builtin::RuleId;
use std::ops::Range;

// Kept internal until the incremental detector modules consume this event.
#[allow(dead_code)]
pub(crate) struct Candidate<'a> {
    pub rule: RuleId,
    pub span: Range<u64>,
    pub value: &'a [u8],
    pub priority: u16,
}
