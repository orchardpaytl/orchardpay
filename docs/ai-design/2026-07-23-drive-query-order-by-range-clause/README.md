# Platform document queries: `order_by`'s direction is only honored when the deciding clause is a range

A Drive query-planner behavior that silently produced wrong results — not
an error, not a slow query, a **wrong answer with no signal anything was
off**. Worth knowing before writing any future "give me the most recent /
oldest N documents" query against Dash Platform.

## The bug this documents

`fetch_latest_message_created_at` (`src/backend_task/orchardpay/messages.rs`)
queried `encryptedMessage` documents for one conversation thread (`refId ==
X`, an equality clause), ordered by `OrderClause { field: "$createdAt",
ascending: false }`, capped to `limit = 1` — intending "the newest message
in this thread." It silently returned the **oldest** message instead. The
query built without error, returned exactly one document as requested, and
that document's `$createdAt` was real data — just the wrong end of the
range. Nothing about the failure mode looked like a bug from the caller's
side.

Symptom in the app: the Most Recent / Contacts tabs showed "Last activity
a day ago" for a contact whose conversation actually had a message from 10
minutes ago.

## The rule

Traced against the actual query planner in the vendored `dash-sdk` git
dependency (`~/.cargo/git/checkouts/platform-*/*/packages/rs-drive/src/query/mod.rs`,
`DocumentQuery::get_non_primary_key_path_query`):

Drive picks one `WhereClause` as the **deciding clause** for a compound-
index query — the clause whose comparison determines the base GroveDB
iteration direction (`left_to_right`). That decision is:

```rust
let left_to_right = if where_clause.operator.is_range() {
    // Range operator (>, >=, <, <=, Between*, In, StartsWith) — direction
    // genuinely comes from order_by:
    let order_clause = self.order_by.get(where_clause.field.as_str())
        .ok_or(/* MissingOrderByForRange: "query must have an orderBy
                  field for each range element" */)?;
    order_clause.ascending
} else {
    // Equal — direction is hardcoded ascending, `order_by` is never consulted:
    true
};
```

(`WhereOperator::is_range()`, `rs-drive/src/query/conditions.rs`: `Equal`
is the only operator where `is_range()` is `false`; every comparison
operator including `LessThan`/`GreaterThan` returns `true`.)

**If every `WhereClause` in your query is an equality match, `order_by`'s
`ascending: false` is silently ignored** — the deciding clause resolves to
one of those equality clauses (whichever the index's `find_best_index`
picks as `last_clause`), `is_range()` is `false` for it, and iteration is
hardcoded ascending. A `limit = 1` on top of that returns the *first*
result in ascending order — the oldest, or otherwise arbitrary-looking,
document — with no error, no warning, nothing in the response that
distinguishes it from a correct result.

## The fix

Add a genuine **range** clause on the *same field* you're ordering by,
alongside whatever equality clause(s) scope the query to the right subset
of documents. That range clause becomes the deciding clause instead, and
*its* direction is read from `order_by` — for real, this time.

For "most recent N" queries this is naturally `field < now` (or
`<= now`); for "oldest N" it's `field > 0` or another sentinel low bound.
Concretely, for the thread-latest-message case:

```rust
query
    .with_where(WhereClause {                    // scopes to the thread
        field: REF_ID_FIELD.to_string(),
        operator: WhereOperator::Equal,
        value: Value::Bytes(ref_id.to_vec()),
    })
    .with_where(WhereClause {                     // the range clause that
        field: "$createdAt".to_string(),          // makes order_by real
        operator: WhereOperator::LessThan,
        value: Value::U64(now_millis),
    })
    .with_order_by(OrderClause {
        field: "$createdAt".to_string(),
        ascending: false,
    });
query.limit = 1;
```

The pre-existing equality clause (`refId`) still correctly narrows to the
right subtree first (used as an "intermediate value" ahead of the range
clause in the path construction) — adding the range clause doesn't
displace it, it just changes which clause drives direction.

`Value::U64` for a millisecond timestamp matches this codebase's existing
convention for `Date`-typed system fields (see
`src/ui/contracts_documents/document_action_screen.rs`'s
`DocumentPropertyType::Date` handling: "expects unix-ms integer"); getting
"now" in millis follows the existing
`SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
as u64` idiom used elsewhere in this codebase (`dashpay/payments.rs`,
`backend_task/grovestark.rs`).

This also explains why `MissingOrderByForRange` ("query must have an
orderBy field for each range element") exists as a hard error: Drive
*requires* a range clause to have a matching `order_by` entry — it just
doesn't require the reverse (an `order_by` entry to have a matching range
clause), which is exactly the gap that let this bug through silently
instead of erroring.

## Related, adjacent gotcha already in this codebase

`src/backend_task/dashpay/contact_requests.rs` has, independently, this
comment on an equality-only query: *"Without this orderBy, the query
returns 0 results even when documents exist."* That's a different failure
mode (missing `order_by` → zero results, rather than present-but-ignored
`order_by` → wrong single result) but the same underlying theme: Drive's
query planner has real, non-obvious constraints around how `WHERE` and
`order_by` clauses interact per index, and getting the combination wrong
fails silently or unhelpfully rather than with a clear validation error
pointing at the actual problem.

## Checklist for a future "give me the most recent / oldest / Nth"
document query

- [ ] Does every `WhereClause` in the query use `WhereOperator::Equal`? If
      so and you also have an `order_by`, **that `order_by`'s direction is
      not being honored** — add a range clause (even a trivially-always-
      true one like `$createdAt < now`) on the field you're ordering by.
- [ ] Does the range clause's field have a matching `order_by` entry?
      Required, or Drive rejects the query outright
      (`MissingOrderByForRange`) — a bit of self-defense here, but only in
      the direction of "range needs order_by," not the reverse.
- [ ] Whichever field you added a range clause on and the field(s) you
      still filter by equality — are they part of one index together, in
      the shape Drive expects (equality-prefix fields, then the
      range/order field)? Check the contract's `indices` array for the
      document type; a mismatched shape produces
      `WhereClauseOnNonIndexedProperty`, not a slow fallback.
- [ ] **Verify against real data with a document count > 1**, not just a
      thread/list with a single document. A query that returns the only
      possible answer trivially "passes" regardless of whether ordering
      actually worked — this bug's own review would have looked correct
      against a one-message thread.

See also: `docs/ai-design/2026-07-19-orchardpay-query-workflow-reference/README.md`
for OrchardPay's full document-query catalog (predates this fix; its
`encryptedMessage` section describes the `refId`/`$ownerId` split but not
this ordering behavior).
