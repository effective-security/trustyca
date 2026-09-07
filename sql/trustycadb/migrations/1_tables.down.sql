BEGIN;

DROP TRIGGER IF EXISTS trigger_budget_account_changes ON trustyca.budget_account;
DROP FUNCTION IF EXISTS trustyca.notify_budget_account_changes();
DROP FUNCTION IF EXISTS notify_budget_account_changes();

DROP TABLE IF EXISTS trustyca.payment;
DROP TABLE IF EXISTS trustyca.budget_ledger;
DROP TABLE IF EXISTS trustyca.budget_account;

DROP TRIGGER IF EXISTS trigger_quota_policy_changes ON trustyca.quota_policy;
DROP FUNCTION IF EXISTS trustyca.notify_quota_policy_changes();
DROP FUNCTION IF EXISTS notify_quota_policy_changes();
DROP FUNCTION IF EXISTS trustyca.notify_quota_changes();
DROP FUNCTION IF EXISTS notify_quota_changes();

DROP TABLE IF EXISTS trustyca.quota_usage_event;
DROP TABLE IF EXISTS trustyca.quota_usage_rollup;
DROP TABLE IF EXISTS trustyca.quota_policy;
DROP TABLE IF EXISTS trustyca.model_key;
DROP TABLE IF EXISTS trustyca.virtual_key;
DROP TABLE IF EXISTS trustyca.llm_model;
DROP TABLE IF EXISTS trustyca.event;
DROP TABLE IF EXISTS trustyca.invite;
DROP VIEW IF EXISTS trustyca.vw_membership_info;
DROP TABLE IF EXISTS trustyca.membership;
DROP TABLE IF EXISTS trustyca.login;
DROP TABLE IF EXISTS trustyca."user";
DROP TABLE IF EXISTS trustyca.project;

DROP FUNCTION IF EXISTS trustyca.create_constraint_if_not_exists(text, text, text, text);
DROP FUNCTION IF EXISTS create_constraint_if_not_exists(text, text, text, text);

COMMIT;
