//! Kittest coverage for `OrchardPayScreen`'s Contacts and Most Recent tabs.
//!
//! Regression coverage for unifying the two tabs' contact sets: both must
//! show the same three handshake stages (`PendingOutbound`,
//! `PendingInboundUnaccepted`, `Established`), differing only in sort
//! order — before this fix, Most Recent showed `Established` only. See
//! `docs/orchardpay/PROTOCOL_DESIGN.md` for the two-anchor handshake this
//! state machine implements.

use crate::support::{fresh_app_context, with_isolated_data_dir};
use dash_sdk::dpp::identity::Identity;
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::version::PlatformVersion;
use dash_sdk::platform::Identifier;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use orchardpay::backend_task::BackendTaskSuccessResult;
use orchardpay::backend_task::orchardpay::contact_anchor::ANCHOR_SIGNAL_AMOUNT_CREDITS;
use orchardpay::backend_task::orchardpay::messages::RecentContactActivity;
use orchardpay::context::AppContext;
use orchardpay::model::orchardpay::OrchardPayContactState;
use orchardpay::model::qualified_identity::encrypted_key_storage::KeyStorage;
use orchardpay::model::qualified_identity::{
    DPNSNameInfo, IdentityStatus, IdentityType, QualifiedIdentity,
};
use orchardpay::ui::ScreenLike;
use orchardpay::ui::orchardpay::orchardpay_screen::{OrchardPayScreen, OrchardPaySubscreen};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The contract ID these tests seed local state under. `AppContext` always
/// resolves *some* real OrchardPay contract ID here — a fresh, isolated data
/// dir (via `with_isolated_data_dir`) has no `.env` of its own yet, so the
/// app's first-run bootstrap writes out the bundled `.env.example` (compiled
/// in via `include_bytes!`), which ships a real, committed Testnet contract
/// ID. There is no runtime setter for `AppContext::orchardpay_contract_id()`,
/// and no way to override it via a process env var either — `Config::load`
/// loads the data dir's `.env` with `dotenvy::from_path_override`, which
/// unconditionally overwrites any env var a test sets first. So tests read
/// back whatever real ID actually got configured instead of trying to inject
/// a fake one.
fn resolve_test_contract_id(app_context: &Arc<AppContext>) -> Identifier {
    app_context
        .orchardpay_contract_id()
        .expect("OrchardPay contract must be configured via the bundled default .env.example")
}

/// Seed a wallet-less identity with a resolvable DPNS name (required to
/// clear `LocalReadiness::NoDpnsName`) and select it as the app-scoped
/// identity, mirroring `dashpay_screen.rs`'s `seed_dp_identity`.
fn seed_identity(app_context: &Arc<AppContext>, byte: u8, dpns_name: &str) -> Identifier {
    let pv = PlatformVersion::latest();
    let identity =
        Identity::create_basic_identity(Identifier::from([byte; 32]), pv).expect("basic identity");
    let id = identity.id();
    let qi = QualifiedIdentity {
        identity,
        associated_voter_identity: None,
        associated_operator_identity: None,
        associated_owner_key_id: None,
        identity_type: IdentityType::User,
        alias: None,
        private_keys: KeyStorage::default(),
        dpns_names: vec![DPNSNameInfo {
            name: dpns_name.to_string(),
            acquired_at: 0,
        }],
        associated_wallets: BTreeMap::new(),
        secret_access: None,
        wallet_index: None,
        top_ups: BTreeMap::new(),
        status: IdentityStatus::Active,
        network: app_context.network(),
    };
    app_context
        .insert_local_qualified_identity(&qi, &None)
        .expect("seed identity");
    app_context.set_selected_identity(Some(id));
    id
}

/// Seeds one contact per handshake stage against `owner_id`, each with a
/// distinct `created_at` so sort order is checkable. Field values other
/// than `name`/`created_at` are never read by rendering, so dummy bytes are
/// fine — except `amount_credits`/`initial_message`, which now render a
/// badge/snippet when set: seeded at the routine default amount and `None`
/// respectively, so this fixture's baseline stays neutral (no badge, no
/// snippet) unless a test explicitly overrides them. Returns
/// `(pending_outbound_id, pending_inbound_id, established_id)`.
fn seed_three_stage_contacts(
    app_context: &Arc<AppContext>,
    contract_id: Identifier,
    owner_id: Identifier,
) -> (Identifier, Identifier, Identifier) {
    let backend = app_context.wallet_backend().expect("wallet backend wired");

    let outbound_id = Identifier::from([101u8; 32]);
    backend
        .orchardpay_set_contact_state(
            &contract_id,
            &owner_id,
            &outbound_id,
            &OrchardPayContactState::PendingOutbound {
                my_reference_id: [1u8; 32],
                my_shie_id: [11u8; 32],
                my_anchor_document_id: [2u8; 32],
                name: Some("Outbound Ollie".to_string()),
                created_at: Some(1_000),
                amount_credits: ANCHOR_SIGNAL_AMOUNT_CREDITS,
                initial_message: None,
            },
        )
        .expect("seed pending-outbound contact");

    let inbound_id = Identifier::from([102u8; 32]);
    backend
        .orchardpay_set_contact_state(
            &contract_id,
            &owner_id,
            &inbound_id,
            &OrchardPayContactState::PendingInboundUnaccepted {
                their_reference_id: [3u8; 32],
                their_shie_id: [13u8; 32],
                their_anchor_document_id: [4u8; 32],
                name: Some("Inbound Ingrid".to_string()),
                created_at: Some(2_000),
                amount_credits: ANCHOR_SIGNAL_AMOUNT_CREDITS,
                initial_message: None,
            },
        )
        .expect("seed pending-inbound contact");

    let established_id = Identifier::from([103u8; 32]);
    backend
        .orchardpay_set_contact_state(
            &contract_id,
            &owner_id,
            &established_id,
            &OrchardPayContactState::Established {
                my_reference_id: [5u8; 32],
                my_shie_id: [15u8; 32],
                my_anchor_document_id: [6u8; 32],
                their_reference_id: [7u8; 32],
                their_shie_id: [17u8; 32],
                counterparty_encryption_pubkey: vec![0u8; 32],
                counterparty_decryption_pubkey: vec![0u8; 32],
                name: Some("Established Eve".to_string()),
                created_at: Some(3_000),
                initial_message: None,
                initial_message_from_me: false,
                initial_message_document_id: None,
            },
        )
        .expect("seed established contact");

    (outbound_id, inbound_id, established_id)
}

fn mount(screen: OrchardPayScreen) -> Harness<'static, OrchardPayScreen> {
    let mut harness = Harness::builder()
        .with_size(egui::vec2(1280.0, 800.0))
        .build_ui_state(
            move |ui, screen: &mut OrchardPayScreen| {
                let _ = screen.ui(ui);
            },
            screen,
        );
    harness.run();
    harness
}

#[test]
fn contacts_tab_shows_all_three_handshake_states() {
    with_isolated_data_dir(|| {
        let (_rt, ctx) = fresh_app_context();
        let contract_id = resolve_test_contract_id(&ctx);

        let owner_id = seed_identity(&ctx, 1, "alice.dash");
        seed_three_stage_contacts(&ctx, contract_id, owner_id);
        ctx.wallet_backend()
            .expect("wallet backend wired")
            .orchardpay_set_has_shielded_address(&contract_id, &owner_id)
            .expect("seed shielded-address flag");

        let screen = OrchardPayScreen::new(&ctx, OrchardPaySubscreen::Contacts);
        let harness = mount(screen);

        assert!(harness.query_by_label("Outbound Ollie").is_some());
        assert!(harness.query_by_label("Waiting for a response…").is_some());
        assert!(harness.query_by_label("Inbound Ingrid").is_some());
        assert!(
            harness
                .query_by_label("Wants to connect with you")
                .is_some()
        );
        assert!(harness.query_by_label("Accept").is_some());
        assert!(harness.query_by_label("Established Eve").is_some());
        assert!(harness.query_by_label("Connected").is_some());
        assert!(harness.query_by_label("Open Conversation").is_some());
    });
}

#[test]
fn most_recent_tab_shows_all_three_handshake_states_not_just_established() {
    with_isolated_data_dir(|| {
        let (_rt, ctx) = fresh_app_context();
        let contract_id = resolve_test_contract_id(&ctx);

        let owner_id = seed_identity(&ctx, 1, "alice.dash");
        let (_outbound_id, _inbound_id, established_id) =
            seed_three_stage_contacts(&ctx, contract_id, owner_id);
        ctx.wallet_backend()
            .expect("wallet backend wired")
            .orchardpay_set_has_shielded_address(&contract_id, &owner_id)
            .expect("seed shielded-address flag");

        let mut screen = OrchardPayScreen::new(&ctx, OrchardPaySubscreen::MostRecent);
        // `render_most_recent` waits on this before rendering anything —
        // seed it directly rather than depending on a real network fetch.
        screen.display_task_result(BackendTaskSuccessResult::OrchardPayRecentActivity(vec![
            RecentContactActivity {
                identity_id: established_id,
                last_activity: Some(3_500),
                has_messages: true,
            },
        ]));
        let harness = mount(screen);

        // The regression this test guards: before this fix, only
        // "Established Eve" would render here.
        assert!(harness.query_by_label("Outbound Ollie").is_some());
        assert!(harness.query_by_label("Inbound Ingrid").is_some());
        assert!(harness.query_by_label("Established Eve").is_some());
    });
}

/// An `Established` contact offers a "Remove Contact" action behind its
/// overflow ("⋯") menu. `PendingOutbound`/`PendingInboundUnaccepted` cards
/// never render an overflow menu at all (only the `Established` arm of
/// `render_contact_card` does), so a single "⋯" query already proves the
/// action is Established-only given `seed_three_stage_contacts` seeds
/// exactly one contact per stage. Stops short of clicking through to the
/// confirmation dialog — like this file's other action assertions (e.g.
/// "Accept"), that requires a resolved signing key/wallet context this
/// screen's precondition guards (`open_remove_contact_confirmation`,
/// mirroring `accept_clicked`) that `seed_identity`'s wallet-less fixture
/// doesn't provide. See `contact_anchor::delete_own_contact_anchor` for why
/// removal is restricted to `Established` contacts.
#[test]
fn established_contact_offers_remove_action_via_overflow_menu() {
    with_isolated_data_dir(|| {
        let (_rt, ctx) = fresh_app_context();
        let contract_id = resolve_test_contract_id(&ctx);

        let owner_id = seed_identity(&ctx, 1, "alice.dash");
        seed_three_stage_contacts(&ctx, contract_id, owner_id);
        ctx.wallet_backend()
            .expect("wallet backend wired")
            .orchardpay_set_has_shielded_address(&contract_id, &owner_id)
            .expect("seed shielded-address flag");

        let screen = OrchardPayScreen::new(&ctx, OrchardPaySubscreen::Contacts);
        let mut harness = mount(screen);

        harness.get_by_label("⋯").click();
        harness.run_steps(3);

        assert!(
            harness.query_by_label("Remove Contact").is_some(),
            "an Established contact must offer a Remove Contact action in its overflow menu"
        );
    });
}

/// Regression: a pending request must outrank an established contact's
/// *older* last message, not sort below every contact that has any message
/// history at all. Before this fix, the sort's primary key was
/// `has_messages` (established-with-messages always first), so a pending
/// request from 7 hours ago rendered below an established contact whose
/// last message was 9 hours ago — reported after manually verifying the
/// unified contact-set fix.
#[test]
fn most_recent_tab_orders_a_newer_pending_request_above_an_older_established_message() {
    with_isolated_data_dir(|| {
        let (_rt, ctx) = fresh_app_context();
        let contract_id = resolve_test_contract_id(&ctx);

        let owner_id = seed_identity(&ctx, 1, "alice.dash");
        let backend = ctx.wallet_backend().expect("wallet backend wired");

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_millis() as u64;
        let nine_hours_ago = now_ms - 9 * 60 * 60 * 1000;
        let seven_hours_ago = now_ms - 7 * 60 * 60 * 1000;

        let established_id = Identifier::from([201u8; 32]);
        backend
            .orchardpay_set_contact_state(
                &contract_id,
                &owner_id,
                &established_id,
                &OrchardPayContactState::Established {
                    my_reference_id: [1u8; 32],
                    my_shie_id: [21u8; 32],
                    my_anchor_document_id: [2u8; 32],
                    their_reference_id: [3u8; 32],
                    their_shie_id: [23u8; 32],
                    counterparty_encryption_pubkey: vec![0u8; 32],
                    counterparty_decryption_pubkey: vec![0u8; 32],
                    name: Some("Older Message Established".to_string()),
                    created_at: Some(nine_hours_ago),
                    initial_message: None,
                    initial_message_from_me: false,
                    initial_message_document_id: None,
                },
            )
            .expect("seed established contact");

        let pending_id = Identifier::from([202u8; 32]);
        backend
            .orchardpay_set_contact_state(
                &contract_id,
                &owner_id,
                &pending_id,
                &OrchardPayContactState::PendingInboundUnaccepted {
                    their_reference_id: [4u8; 32],
                    their_shie_id: [24u8; 32],
                    their_anchor_document_id: [5u8; 32],
                    name: Some("Newer Pending Request".to_string()),
                    created_at: Some(seven_hours_ago),
                    amount_credits: ANCHOR_SIGNAL_AMOUNT_CREDITS,
                    initial_message: None,
                },
            )
            .expect("seed pending contact");

        backend
            .orchardpay_set_has_shielded_address(&contract_id, &owner_id)
            .expect("seed shielded-address flag");

        let mut screen = OrchardPayScreen::new(&ctx, OrchardPaySubscreen::MostRecent);
        screen.display_task_result(BackendTaskSuccessResult::OrchardPayRecentActivity(vec![
            RecentContactActivity {
                identity_id: established_id,
                last_activity: Some(nine_hours_ago),
                has_messages: true,
            },
        ]));
        let harness = mount(screen);

        let pending_top = harness.get_by_label("Newer Pending Request").rect().top();
        let established_top = harness
            .get_by_label("Older Message Established")
            .rect()
            .top();
        assert!(
            pending_top < established_top,
            "the 7-hour-old pending request must render above the 9-hour-old \
             established contact's last message, but pending_top={pending_top} \
             established_top={established_top}"
        );
    });
}

#[test]
fn most_recent_header_text_no_longer_says_established() {
    with_isolated_data_dir(|| {
        let (_rt, ctx) = fresh_app_context();
        let contract_id = resolve_test_contract_id(&ctx);

        let owner_id = seed_identity(&ctx, 1, "alice.dash");
        ctx.wallet_backend()
            .expect("wallet backend wired")
            .orchardpay_set_has_shielded_address(&contract_id, &owner_id)
            .expect("seed shielded-address flag");

        let mut screen = OrchardPayScreen::new(&ctx, OrchardPaySubscreen::MostRecent);
        screen.display_task_result(BackendTaskSuccessResult::OrchardPayRecentActivity(vec![]));
        let harness = mount(screen);

        assert!(
            harness
                .query_by_label(
                    "All your contacts, ordered by their conversation's most recent activity."
                )
                .is_some()
        );
        assert!(
            harness
                .query_by_label(
                    "Established contacts, ordered by their conversation's most recent activity."
                )
                .is_none()
        );
    });
}

/// A pending request's attached message renders as a truncated, quoted
/// snippet directly on the row, in both the Contacts and Most Recent tabs —
/// the "visible in both tabs" requirement is satisfied for free since both
/// share `render_contact_card`.
#[test]
fn pending_outbound_row_shows_message_snippet_when_present() {
    with_isolated_data_dir(|| {
        let (_rt, ctx) = fresh_app_context();
        let contract_id = resolve_test_contract_id(&ctx);
        let owner_id = seed_identity(&ctx, 1, "alice.dash");
        let backend = ctx.wallet_backend().expect("wallet backend wired");

        let counterparty_id = Identifier::from([111u8; 32]);
        backend
            .orchardpay_set_contact_state(
                &contract_id,
                &owner_id,
                &counterparty_id,
                &OrchardPayContactState::PendingOutbound {
                    my_reference_id: [1u8; 32],
                    my_shie_id: [31u8; 32],
                    my_anchor_document_id: [2u8; 32],
                    name: Some("Message Mia".to_string()),
                    created_at: Some(1_000),
                    amount_credits: ANCHOR_SIGNAL_AMOUNT_CREDITS,
                    initial_message: Some("hey its me Paul".to_string()),
                },
            )
            .expect("seed contact with a message");
        backend
            .orchardpay_set_has_shielded_address(&contract_id, &owner_id)
            .expect("seed shielded-address flag");

        let screen = OrchardPayScreen::new(&ctx, OrchardPaySubscreen::Contacts);
        let harness = mount(screen);

        assert!(
            harness.query_by_label("\"hey its me Paul\"").is_some(),
            "Contacts tab must show the attached message as a quoted snippet"
        );
    });
}

/// The routine default signal amount (`ANCHOR_SIGNAL_AMOUNT_CREDITS`) never
/// shows an amount badge — it would be repetitive noise on every plain "Add
/// Contact" row.
#[test]
fn pending_row_hides_amount_badge_at_default_signal_amount() {
    with_isolated_data_dir(|| {
        let (_rt, ctx) = fresh_app_context();
        let contract_id = resolve_test_contract_id(&ctx);
        let owner_id = seed_identity(&ctx, 1, "alice.dash");
        seed_three_stage_contacts(&ctx, contract_id, owner_id);
        ctx.wallet_backend()
            .expect("wallet backend wired")
            .orchardpay_set_has_shielded_address(&contract_id, &owner_id)
            .expect("seed shielded-address flag");

        let screen = OrchardPayScreen::new(&ctx, OrchardPaySubscreen::Contacts);
        let harness = mount(screen);

        assert!(
            harness.query_by_label_contains("Sent with").is_none(),
            "a request at the routine default signal amount must never show an amount badge"
        );
    });
}

/// An amount meaningfully above the default signal amount (Direct Send's
/// bundled-request path) shows an amount badge on the pending row.
#[test]
fn pending_row_shows_amount_badge_above_default_signal_amount() {
    with_isolated_data_dir(|| {
        let (_rt, ctx) = fresh_app_context();
        let contract_id = resolve_test_contract_id(&ctx);
        let owner_id = seed_identity(&ctx, 1, "alice.dash");
        let backend = ctx.wallet_backend().expect("wallet backend wired");

        let counterparty_id = Identifier::from([112u8; 32]);
        backend
            .orchardpay_set_contact_state(
                &contract_id,
                &owner_id,
                &counterparty_id,
                &OrchardPayContactState::PendingOutbound {
                    my_reference_id: [1u8; 32],
                    my_shie_id: [32u8; 32],
                    my_anchor_document_id: [2u8; 32],
                    name: Some("Bundled Bob".to_string()),
                    created_at: Some(1_000),
                    amount_credits: ANCHOR_SIGNAL_AMOUNT_CREDITS * 10,
                    initial_message: None,
                },
            )
            .expect("seed contact with a bundled amount");
        backend
            .orchardpay_set_has_shielded_address(&contract_id, &owner_id)
            .expect("seed shielded-address flag");

        let screen = OrchardPayScreen::new(&ctx, OrchardPaySubscreen::Contacts);
        let harness = mount(screen);

        assert!(
            harness.query_by_label_contains("Sent with").is_some(),
            "a request bundled with an above-default amount must show an amount badge"
        );
    });
}

/// Once `Established`, a row shows neither the message snippet nor the
/// amount badge — both belong to the pending phase only; the message lives
/// on in the conversation thread instead (see `messages::load_thread`'s
/// synthetic first bubble).
#[test]
fn established_row_never_shows_amount_badge_or_snippet() {
    with_isolated_data_dir(|| {
        let (_rt, ctx) = fresh_app_context();
        let contract_id = resolve_test_contract_id(&ctx);
        let owner_id = seed_identity(&ctx, 1, "alice.dash");
        let backend = ctx.wallet_backend().expect("wallet backend wired");

        let counterparty_id = Identifier::from([113u8; 32]);
        backend
            .orchardpay_set_contact_state(
                &contract_id,
                &owner_id,
                &counterparty_id,
                &OrchardPayContactState::Established {
                    my_reference_id: [1u8; 32],
                    my_shie_id: [33u8; 32],
                    my_anchor_document_id: [2u8; 32],
                    their_reference_id: [3u8; 32],
                    their_shie_id: [34u8; 32],
                    counterparty_encryption_pubkey: vec![0u8; 32],
                    counterparty_decryption_pubkey: vec![0u8; 32],
                    name: Some("Connected Carl".to_string()),
                    created_at: Some(1_000),
                    initial_message: Some("hey its me Paul".to_string()),
                    initial_message_from_me: true,
                    initial_message_document_id: Some([4u8; 32]),
                },
            )
            .expect("seed established contact carrying a message");
        backend
            .orchardpay_set_has_shielded_address(&contract_id, &owner_id)
            .expect("seed shielded-address flag");

        let screen = OrchardPayScreen::new(&ctx, OrchardPaySubscreen::Contacts);
        let harness = mount(screen);

        assert!(
            harness.query_by_label("\"hey its me Paul\"").is_none(),
            "an Established row must never show the message snippet"
        );
        assert!(
            harness.query_by_label_contains("Sent with").is_none(),
            "an Established row must never show an amount badge"
        );
    });
}
