```
Schema: trustyca
Table: apikey

┌─────┬────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────────────────────┐
│ ORD │    NAME    │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │         REF         │
├─────┼────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────────────────────┤
│ 1   │ id         │ bigint                   │ int8        │      │     │ YES   │                     │
│ 2   │ org_id     │ bigint                   │ int8        │      │     │ YES   │ trustyca.project.id │
│ 3   │ project_id │ bigint                   │ int8        │ YES  │     │ YES   │ trustyca.project.id │
│ 4   │ key        │ character varying        │ varchar     │      │ 128 │ YES   │                     │
│ 5   │ secret     │ character varying        │ varchar     │      │ 128 │       │                     │
│ 6   │ label      │ character varying        │ varchar     │      │ 260 │       │                     │
│ 7   │ scopes     │ ARRAY                    │ _varchar    │      │     │       │                     │
│ 8   │ metadata   │ jsonb                    │ jsonb       │ YES  │     │       │                     │
│ 9   │ status     │ integer                  │ int4        │      │     │       │                     │
│ 10  │ created_at │ timestamp with time zone │ timestamptz │      │     │       │                     │
│ 11  │ expires_at │ timestamp with time zone │ timestamptz │ YES  │     │       │                     │
│ 12  │ used_at    │ timestamp with time zone │ timestamptz │ YES  │     │       │                     │
│ 13  │ used_count │ integer                  │ int4        │      │     │       │                     │
└─────┴────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────────────────────┘

Indexes:
┌────────────────────────┬─────────┬────────┬────────────────────┐
│          NAME          │ PRIMARY │ UNIQUE │      COLUMNS       │
├────────────────────────┼─────────┼────────┼────────────────────┤
│ apikey_key             │         │ YES    │ key                │
│ apikey_pkey            │ YES     │ YES    │ id                 │
│ idx_apikey_org_project │         │        │ org_id, project_id │
└────────────────────────┴─────────┴────────┴────────────────────┘

Schema: trustyca
Table: certificate

┌─────┬───────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────┐
│ ORD │     NAME      │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │ REF │
├─────┼───────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────┤
│ 1   │ id            │ bigint                   │ int8        │      │     │ YES   │     │
│ 2   │ org_id        │ bigint                   │ int8        │ YES  │     │ YES   │     │
│ 3   │ project_id    │ bigint                   │ int8        │ YES  │     │ YES   │     │
│ 4   │ skid          │ character varying        │ varchar     │      │ 64  │ YES   │     │
│ 5   │ ikid          │ character varying        │ varchar     │      │ 64  │ YES   │     │
│ 6   │ serial_number │ character varying        │ varchar     │      │ 64  │ YES   │     │
│ 7   │ not_before    │ timestamp with time zone │ timestamptz │      │     │       │     │
│ 8   │ not_after     │ timestamp with time zone │ timestamptz │      │     │ YES   │     │
│ 9   │ subject       │ character varying        │ varchar     │      │ 260 │       │     │
│ 10  │ issuer        │ character varying        │ varchar     │      │ 260 │       │     │
│ 11  │ sha256        │ character varying        │ varchar     │      │ 64  │ YES   │     │
│ 12  │ profile       │ character varying        │ varchar     │      │ 64  │       │     │
│ 13  │ label         │ character varying        │ varchar     │      │ 260 │       │     │
│ 14  │ locations     │ ARRAY                    │ _varchar    │      │     │       │     │
│ 15  │ metadata      │ jsonb                    │ jsonb       │      │     │       │     │
│ 16  │ pem           │ text                     │ text        │      │     │       │     │
│ 17  │ issuers_pem   │ text                     │ text        │      │     │       │     │
│ 18  │ status        │ integer                  │ int4        │      │     │ YES   │     │
│ 19  │ created_at    │ timestamp with time zone │ timestamptz │      │     │       │     │
└─────┴───────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────┘

Indexes:
┌─────────────────────────────────────────────┬─────────┬────────┬───────────────────────────────────────┐
│                    NAME                     │ PRIMARY │ UNIQUE │                COLUMNS                │
├─────────────────────────────────────────────┼─────────┼────────┼───────────────────────────────────────┤
│ certificate_pkey                            │ YES     │ YES    │ id                                    │
│ idx_certificate_notafter                    │         │        │ not_after                             │
│ idx_certificate_org_id_desc                 │         │        │ id, org_id                            │
│ idx_certificate_org_ikid_id_desc            │         │        │ id, org_id, ikid                      │
│ idx_certificate_org_project_id_desc         │         │        │ org_id, project_id, id                │
│ idx_certificate_org_project_notafter        │         │        │ project_id, org_id, not_after         │
│ idx_certificate_org_project_status_notafter │         │        │ status, org_id, project_id, not_after │
│ idx_certificate_skid                        │         │        │ skid                                  │
│ unique_certificate_ikid_serial              │         │ YES    │ serial_number, ikid                   │
│ unique_certificate_sha256                   │         │ YES    │ sha256                                │
└─────────────────────────────────────────────┴─────────┴────────┴───────────────────────────────────────┘

Schema: trustyca
Table: certificate_profile

┌─────┬──────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────┐
│ ORD │     NAME     │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │ REF │
├─────┼──────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────┤
│ 1   │ id           │ bigint                   │ int8        │      │     │ YES   │     │
│ 2   │ org_id       │ bigint                   │ int8        │ YES  │     │ YES   │     │
│ 3   │ project_id   │ bigint                   │ int8        │ YES  │     │ YES   │     │
│ 4   │ label        │ character varying        │ varchar     │      │ 64  │ YES   │     │
│ 5   │ issuer_label │ character varying        │ varchar     │      │ 64  │ YES   │     │
│ 6   │ status       │ integer                  │ int4        │      │     │       │     │
│ 7   │ config       │ jsonb                    │ jsonb       │      │     │       │     │
│ 8   │ created_at   │ timestamp with time zone │ timestamptz │      │     │       │     │
│ 9   │ updated_at   │ timestamp with time zone │ timestamptz │      │     │       │     │
└─────┴──────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────┘

Indexes:
┌──────────────────────────────────────────────┬─────────┬────────┬───────────────────────────┐
│                     NAME                     │ PRIMARY │ UNIQUE │          COLUMNS          │
├──────────────────────────────────────────────┼─────────┼────────┼───────────────────────────┤
│ certificate_profile_pkey                     │ YES     │ YES    │ id                        │
│ idx_certificate_profile_org_issuer           │         │        │ org_id, issuer_label      │
│ unique_certificate_profile_org_project_label │         │ YES    │ org_id, project_id, label │
└──────────────────────────────────────────────┴─────────┴────────┴───────────────────────────┘

Schema: trustyca
Table: crl

┌─────┬─────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬────────────────────┐
│ ORD │    NAME     │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │        REF         │
├─────┼─────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼────────────────────┤
│ 1   │ id          │ bigint                   │ int8        │      │     │ YES   │                    │
│ 2   │ org_id      │ bigint                   │ int8        │ YES  │     │       │                    │
│ 3   │ project_id  │ bigint                   │ int8        │ YES  │     │       │                    │
│ 4   │ issuer_id   │ bigint                   │ int8        │      │     │       │ trustyca.issuer.id │
│ 5   │ ikid        │ character varying        │ varchar     │      │ 64  │ YES   │                    │
│ 6   │ crl_number  │ bigint                   │ int8        │      │     │       │                    │
│ 7   │ this_update │ timestamp with time zone │ timestamptz │      │     │       │                    │
│ 8   │ next_update │ timestamp with time zone │ timestamptz │      │     │ YES   │                    │
│ 9   │ issuer      │ character varying        │ varchar     │      │ 260 │       │                    │
│ 10  │ pem         │ text                     │ text        │      │     │       │                    │
│ 11  │ locations   │ ARRAY                    │ _varchar    │      │     │       │                    │
│ 12  │ created_at  │ timestamp with time zone │ timestamptz │      │     │       │                    │
└─────┴─────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴────────────────────┘

Indexes:
┌─────────────────────┬─────────┬────────┬─────────────┐
│        NAME         │ PRIMARY │ UNIQUE │   COLUMNS   │
├─────────────────────┼─────────┼────────┼─────────────┤
│ crl_pkey            │ YES     │ YES    │ id          │
│ idx_crl_next_update │         │        │ next_update │
│ unique_crl_ikid     │         │ YES    │ ikid        │
└─────────────────────┴─────────┴────────┴─────────────┘

Schema: trustyca
Table: event

┌─────┬─────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────────────────────┐
│ ORD │    NAME     │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │         REF         │
├─────┼─────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────────────────────┤
│ 1   │ id          │ bigint                   │ int8        │      │     │ YES   │                     │
│ 2   │ org_id      │ bigint                   │ int8        │ YES  │     │ YES   │ trustyca.org.id     │
│ 3   │ project_id  │ bigint                   │ int8        │ YES  │     │ YES   │ trustyca.project.id │
│ 4   │ type        │ integer                  │ int4        │      │     │ YES   │                     │
│ 5   │ title       │ character varying        │ varchar     │      │ 256 │       │                     │
│ 6   │ description │ text                     │ text        │ YES  │     │       │                     │
│ 7   │ metadata    │ jsonb                    │ jsonb       │      │     │       │                     │
│ 8   │ ref_id      │ bigint                   │ int8        │ YES  │     │ YES   │                     │
│ 9   │ email       │ character varying        │ varchar     │ YES  │ 160 │ YES   │                     │
│ 10  │ source      │ character varying        │ varchar     │ YES  │ 256 │       │                     │
│ 11  │ created_at  │ timestamp with time zone │ timestamptz │      │     │ YES   │                     │
└─────┴─────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────────────────────┘

Indexes:
┌───────────────────────────────────────┬─────────┬────────┬────────────────────────────────────┐
│                 NAME                  │ PRIMARY │ UNIQUE │              COLUMNS               │
├───────────────────────────────────────┼─────────┼────────┼────────────────────────────────────┤
│ event_pkey                            │ YES     │ YES    │ id                                 │
│ idx_event_email                       │         │        │ email                              │
│ idx_event_org_created_id_desc         │         │        │ id, org_id, created_at             │
│ idx_event_org_id                      │         │        │ org_id                             │
│ idx_event_org_project_created_id_desc │         │        │ org_id, id, project_id, created_at │
│ idx_event_org_ref_id                  │         │        │ org_id, ref_id                     │
│ idx_event_type                        │         │        │ type                               │
└───────────────────────────────────────┴─────────┴────────┴────────────────────────────────────┘

Schema: trustyca
Table: invite

┌─────┬────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────────────────────┐
│ ORD │    NAME    │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │         REF         │
├─────┼────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────────────────────┤
│ 1   │ id         │ bigint                   │ int8        │      │     │ YES   │                     │
│ 2   │ org_id     │ bigint                   │ int8        │      │     │ YES   │ trustyca.project.id │
│ 3   │ project_id │ bigint                   │ int8        │ YES  │     │ YES   │ trustyca.project.id │
│ 4   │ inviter_id │ bigint                   │ int8        │      │     │       │ trustyca.user.id    │
│ 5   │ email      │ character varying        │ varchar     │      │ 160 │ YES   │                     │
│ 6   │ role       │ integer                  │ int4        │      │     │       │                     │
│ 7   │ created_at │ timestamp with time zone │ timestamptz │      │     │       │                     │
│ 8   │ expires_at │ timestamp with time zone │ timestamptz │ YES  │     │       │                     │
└─────┴────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────────────────────┘

Indexes:
┌─────────────────────────────────┬─────────┬────────┬───────────────────────────┐
│              NAME               │ PRIMARY │ UNIQUE │          COLUMNS          │
├─────────────────────────────────┼─────────┼────────┼───────────────────────────┤
│ idx_invite_email                │         │        │ email                     │
│ idx_invite_org_project          │         │        │ org_id, project_id        │
│ invite_pkey                     │ YES     │ YES    │ id                        │
│ unique_invite_org_project_email │         │ YES    │ email, org_id, project_id │
└─────────────────────────────────┴─────────┴────────┴───────────────────────────┘

Schema: trustyca
Table: issuer

┌─────┬───────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────┐
│ ORD │     NAME      │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │ REF │
├─────┼───────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────┤
│ 1   │ id            │ bigint                   │ int8        │      │     │ YES   │     │
│ 2   │ org_id        │ bigint                   │ int8        │ YES  │     │ YES   │     │
│ 3   │ project_id    │ bigint                   │ int8        │ YES  │     │ YES   │     │
│ 4   │ label         │ character varying        │ varchar     │      │ 64  │ YES   │     │
│ 5   │ type          │ integer                  │ int4        │      │     │       │     │
│ 6   │ status        │ integer                  │ int4        │      │     │ YES   │     │
│ 7   │ parent_id     │ bigint                   │ int8        │ YES  │     │ YES   │     │
│ 8   │ skid          │ character varying        │ varchar     │      │ 64  │ YES   │     │
│ 9   │ ikid          │ character varying        │ varchar     │      │ 64  │       │     │
│ 10  │ serial_number │ character varying        │ varchar     │      │ 64  │       │     │
│ 11  │ subject       │ character varying        │ varchar     │      │ 260 │       │     │
│ 12  │ issuer        │ character varying        │ varchar     │      │ 260 │       │     │
│ 13  │ sha256        │ character varying        │ varchar     │      │ 64  │       │     │
│ 14  │ not_before    │ timestamp with time zone │ timestamptz │ YES  │     │       │     │
│ 15  │ not_after     │ timestamp with time zone │ timestamptz │ YES  │     │ YES   │     │
│ 16  │ pem           │ text                     │ text        │      │     │       │     │
│ 17  │ chain_pem     │ text                     │ text        │      │     │       │     │
│ 18  │ root_pem      │ text                     │ text        │      │     │       │     │
│ 19  │ csr_pem       │ text                     │ text        │      │     │       │     │
│ 20  │ key_provider  │ character varying        │ varchar     │      │ 64  │       │     │
│ 21  │ key_id        │ character varying        │ varchar     │      │ 260 │       │     │
│ 22  │ key_protected │ text                     │ text        │ YES  │     │       │     │
│ 23  │ config        │ jsonb                    │ jsonb       │      │     │       │     │
│ 24  │ crl_number    │ bigint                   │ int8        │      │     │       │     │
│ 25  │ created_at    │ timestamp with time zone │ timestamptz │      │     │       │     │
│ 26  │ updated_at    │ timestamp with time zone │ timestamptz │      │     │       │     │
└─────┴───────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────┘

Indexes:
┌─────────────────────────────────┬─────────┬────────┬────────────────────────────┐
│              NAME               │ PRIMARY │ UNIQUE │          COLUMNS           │
├─────────────────────────────────┼─────────┼────────┼────────────────────────────┤
│ idx_issuer_notafter             │         │        │ not_after                  │
│ idx_issuer_org_project_status   │         │        │ org_id, project_id, status │
│ idx_issuer_parent               │         │        │ parent_id                  │
│ issuer_pkey                     │ YES     │ YES    │ id                         │
│ unique_issuer_org_project_label │         │ YES    │ org_id, project_id, label  │
│ unique_issuer_skid              │         │ YES    │ skid                       │
└─────────────────────────────────┴─────────┴────────┴────────────────────────────┘

Schema: trustyca
Table: login

┌─────┬──────────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────┐
│ ORD │       NAME       │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │ REF │
├─────┼──────────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────┤
│ 1   │ id               │ bigint                   │ int8        │      │     │ YES   │     │
│ 2   │ external_id      │ character varying        │ varchar     │      │ 64  │       │     │
│ 3   │ provider         │ integer                  │ int4        │      │     │ YES   │     │
│ 4   │ email            │ character varying        │ varchar     │      │ 160 │ YES   │     │
│ 5   │ email_verified   │ boolean                  │ bool        │      │     │       │     │
│ 6   │ name             │ character varying        │ varchar     │      │ 64  │       │     │
│ 7   │ access_token     │ text                     │ text        │      │     │       │     │
│ 8   │ refresh_token    │ text                     │ text        │      │     │       │     │
│ 9   │ token_expires_at │ timestamp with time zone │ timestamptz │ YES  │     │       │     │
│ 10  │ count            │ integer                  │ int4        │      │     │       │     │
│ 11  │ last_at          │ timestamp with time zone │ timestamptz │ YES  │     │ YES   │     │
└─────┴──────────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────┘

Indexes:
┌─────────────────────────────┬─────────┬────────┬─────────────────┐
│            NAME             │ PRIMARY │ UNIQUE │     COLUMNS     │
├─────────────────────────────┼─────────┼────────┼─────────────────┤
│ idx_login_email             │         │        │ email           │
│ idx_login_last_at           │         │        │ last_at         │
│ login_pkey                  │ YES     │ YES    │ id              │
│ unique_login_provider_email │         │ YES    │ provider, email │
└─────────────────────────────┴─────────┴────────┴─────────────────┘

Schema: trustyca
Table: membership

┌─────┬────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────────────────────┐
│ ORD │    NAME    │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │         REF         │
├─────┼────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────────────────────┤
│ 1   │ id         │ bigint                   │ int8        │      │     │ YES   │                     │
│ 2   │ org_id     │ bigint                   │ int8        │      │     │ YES   │ trustyca.project.id │
│ 3   │ project_id │ bigint                   │ int8        │ YES  │     │ YES   │ trustyca.project.id │
│ 4   │ user_id    │ bigint                   │ int8        │      │     │ YES   │ trustyca.user.id    │
│ 5   │ role       │ integer                  │ int4        │      │     │       │                     │
│ 6   │ created_at │ timestamp with time zone │ timestamptz │      │     │       │                     │
└─────┴────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────────────────────┘

Indexes:
┌────────────────────────────────────┬─────────┬────────┬─────────────────────────────┐
│                NAME                │ PRIMARY │ UNIQUE │           COLUMNS           │
├────────────────────────────────────┼─────────┼────────┼─────────────────────────────┤
│ idx_membership_org_project         │         │        │ org_id, project_id          │
│ idx_membership_user_id             │         │        │ user_id                     │
│ membership_pkey                    │ YES     │ YES    │ id                          │
│ unique_membership_org_project_user │         │ YES    │ user_id, org_id, project_id │
└────────────────────────────────────┴─────────┴────────┴─────────────────────────────┘

Schema: trustyca
Table: org

┌─────┬─────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────┐
│ ORD │    NAME     │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │ REF │
├─────┼─────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────┤
│ 1   │ id          │ bigint                   │ int8        │      │     │ YES   │     │
│ 2   │ alias       │ character varying        │ varchar     │      │ 32  │ YES   │     │
│ 3   │ name        │ character varying        │ varchar     │      │ 64  │ YES   │     │
│ 4   │ description │ text                     │ text        │ YES  │     │       │     │
│ 5   │ status      │ integer                  │ int4        │      │     │       │     │
│ 6   │ created_at  │ timestamp with time zone │ timestamptz │      │     │       │     │
└─────┴─────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────┘

Indexes:
┌──────────────────┬─────────┬────────┬──────────┐
│       NAME       │ PRIMARY │ UNIQUE │ COLUMNS  │
├──────────────────┼─────────┼────────┼──────────┤
│ idx_org_name_id  │         │        │ id, name │
│ org_pkey         │ YES     │ YES    │ id       │
│ unique_org_alias │         │ YES    │ alias    │
└──────────────────┴─────────┴────────┴──────────┘

Schema: trustyca
Table: project

┌─────┬─────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────────────────┐
│ ORD │    NAME     │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │       REF       │
├─────┼─────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────────────────┤
│ 1   │ id          │ bigint                   │ int8        │      │     │ YES   │                 │
│ 2   │ org_id      │ bigint                   │ int8        │      │     │ YES   │ trustyca.org.id │
│ 3   │ alias       │ character varying        │ varchar     │      │ 64  │ YES   │                 │
│ 4   │ name        │ character varying        │ varchar     │      │ 64  │ YES   │                 │
│ 5   │ description │ text                     │ text        │ YES  │     │       │                 │
│ 6   │ status      │ integer                  │ int4        │      │     │ YES   │                 │
│ 7   │ created_at  │ timestamp with time zone │ timestamptz │      │     │       │                 │
│ 8   │ updated_at  │ timestamp with time zone │ timestamptz │      │     │       │                 │
└─────┴─────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────────────────┘

Indexes:
┌──────────────────────────┬─────────┬────────┬────────────────┐
│           NAME           │ PRIMARY │ UNIQUE │    COLUMNS     │
├──────────────────────────┼─────────┼────────┼────────────────┤
│ idx_project_name_id      │         │        │ name, id       │
│ idx_project_org_status   │         │        │ org_id, status │
│ project_pkey             │ YES     │ YES    │ id             │
│ unique_project_org_alias │         │ YES    │ alias, org_id  │
│ unique_project_org_id    │         │ YES    │ org_id, id     │
└──────────────────────────┴─────────┴────────┴────────────────┘

Schema: trustyca
Table: revoked

┌─────┬────────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────────────────────────┐
│ ORD │      NAME      │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │           REF           │
├─────┼────────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────────────────────────┤
│ 1   │ id             │ bigint                   │ int8        │      │     │ YES   │                         │
│ 2   │ org_id         │ bigint                   │ int8        │ YES  │     │ YES   │                         │
│ 3   │ project_id     │ bigint                   │ int8        │ YES  │     │ YES   │                         │
│ 4   │ certificate_id │ bigint                   │ int8        │      │     │ YES   │ trustyca.certificate.id │
│ 5   │ ikid           │ character varying        │ varchar     │      │ 64  │ YES   │                         │
│ 6   │ serial_number  │ character varying        │ varchar     │      │ 64  │ YES   │                         │
│ 7   │ not_after      │ timestamp with time zone │ timestamptz │      │     │ YES   │                         │
│ 8   │ revoked_at     │ timestamp with time zone │ timestamptz │      │     │       │                         │
│ 9   │ reason         │ integer                  │ int4        │      │     │       │                         │
│ 10  │ reason_text    │ character varying        │ varchar     │      │ 260 │       │                         │
└─────┴────────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────────────────────────┘

Indexes:
┌─────────────────────────────────┬─────────┬────────┬────────────────────────┐
│              NAME               │ PRIMARY │ UNIQUE │        COLUMNS         │
├─────────────────────────────────┼─────────┼────────┼────────────────────────┤
│ idx_revoked_ikid_notafter       │         │        │ ikid, not_after        │
│ idx_revoked_ikid_serial         │         │ YES    │ ikid, serial_number    │
│ idx_revoked_org_project_id_desc │         │        │ id, org_id, project_id │
│ revoked_pkey                    │ YES     │ YES    │ id                     │
│ unique_revoked_certificate      │         │ YES    │ certificate_id         │
└─────────────────────────────────┴─────────┴────────┴────────────────────────┘

Schema: trustyca
Table: root_certificate

┌─────┬────────────┬──────────────────────────┬─────────────┬──────┬─────┬───────┬─────┐
│ ORD │    NAME    │           TYPE           │     UDT     │ NULL │ MAX │ INDEX │ REF │
├─────┼────────────┼──────────────────────────┼─────────────┼──────┼─────┼───────┼─────┤
│ 1   │ id         │ bigint                   │ int8        │      │     │ YES   │     │
│ 2   │ org_id     │ bigint                   │ int8        │ YES  │     │ YES   │     │
│ 3   │ skid       │ character varying        │ varchar     │      │ 64  │ YES   │     │
│ 4   │ not_before │ timestamp with time zone │ timestamptz │      │     │       │     │
│ 5   │ not_after  │ timestamp with time zone │ timestamptz │      │     │ YES   │     │
│ 6   │ subject    │ character varying        │ varchar     │      │ 260 │       │     │
│ 7   │ sha256     │ character varying        │ varchar     │      │ 64  │ YES   │     │
│ 8   │ trust      │ integer                  │ int4        │      │     │       │     │
│ 9   │ pem        │ text                     │ text        │      │     │       │     │
│ 10  │ created_at │ timestamp with time zone │ timestamptz │      │     │       │     │
└─────┴────────────┴──────────────────────────┴─────────────┴──────┴─────┴───────┴─────┘

Indexes:
┌────────────────────────────────┬─────────┬────────┬───────────┐
│              NAME              │ PRIMARY │ UNIQUE │  COLUMNS  │
├────────────────────────────────┼─────────┼────────┼───────────┤
│ idx_root_certificate_notafter  │         │        │ not_after │
│ idx_root_certificate_org       │         │        │ org_id    │
│ idx_root_certificate_skid      │         │        │ skid      │
│ root_certificate_pkey          │ YES     │ YES    │ id        │
│ unique_root_certificate_sha256 │         │ YES    │ sha256    │
└────────────────────────────────┴─────────┴────────┴───────────┘

Schema: trustyca
Table: schema_migrations

┌─────┬─────────┬─────────┬──────┬──────┬─────┬───────┬─────┐
│ ORD │  NAME   │  TYPE   │ UDT  │ NULL │ MAX │ INDEX │ REF │
├─────┼─────────┼─────────┼──────┼──────┼─────┼───────┼─────┤
│ 1   │ version │ bigint  │ int8 │      │     │ YES   │     │
│ 2   │ dirty   │ boolean │ bool │      │     │       │     │
└─────┴─────────┴─────────┴──────┴──────┴─────┴───────┴─────┘

Indexes:
┌────────────────────────┬─────────┬────────┬─────────┐
│          NAME          │ PRIMARY │ UNIQUE │ COLUMNS │
├────────────────────────┼─────────┼────────┼─────────┤
│ schema_migrations_pkey │ YES     │ YES    │ version │
└────────────────────────┴─────────┴────────┴─────────┘

Schema: trustyca
Table: user

┌─────┬────────────────┬───────────────────┬─────────┬──────┬─────┬───────┬─────┐
│ ORD │      NAME      │       TYPE        │   UDT   │ NULL │ MAX │ INDEX │ REF │
├─────┼────────────────┼───────────────────┼─────────┼──────┼─────┼───────┼─────┤
│ 1   │ id             │ bigint            │ int8    │      │     │ YES   │     │
│ 2   │ email          │ character varying │ varchar │      │ 160 │ YES   │     │
│ 3   │ email_verified │ boolean           │ bool    │      │     │       │     │
│ 4   │ name           │ character varying │ varchar │      │ 64  │       │     │
└─────┴────────────────┴───────────────────┴─────────┴──────┴─────┴───────┴─────┘

Indexes:
┌───────────────────┬─────────┬────────┬─────────┐
│       NAME        │ PRIMARY │ UNIQUE │ COLUMNS │
├───────────────────┼─────────┼────────┼─────────┤
│ unique_user_email │         │ YES    │ email   │
│ user_pkey         │ YES     │ YES    │ id      │
└───────────────────┴─────────┴────────┴─────────┘

```
