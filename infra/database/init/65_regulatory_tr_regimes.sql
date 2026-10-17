-- Turkish regulatory clocks (W0.42): KVKK, BDDK and USOM / SOME next to DORA
-- and NIS2 (50_regulatory_clocks.sql). 50 created both CHECK constraints for
-- the two EU regimes only; this file replaces them with the full set, so a
-- fresh install (50 then 65) and an upgraded one end the same. Rerunnable: the
-- constraint is dropped by name and added again. The regimes and their
-- instants and report kinds are core/compliance/clocks.py INSTANTS and
-- core/compliance/regulatory_drafts.py KINDS; keep the three in step.

ALTER TABLE regulatory_clock_events
    DROP CONSTRAINT IF EXISTS regulatory_clock_events_instant_check;
ALTER TABLE regulatory_clock_events
    ADD CONSTRAINT regulatory_clock_events_instant_check CHECK (
        (regime = 'dora' AND instant IN
            ('aware_at', 'classification_at', 'notified_at', 'last_intermediate_at', 'final_at'))
        OR (regime = 'nis2' AND instant IN
            ('aware_at', 'early_warning_at', 'notified_at', 'final_at'))
        OR (regime = 'kvkk' AND instant IN
            ('aware_at', 'notified_at', 'subjects_notified_at'))
        OR (regime = 'bddk' AND instant IN
            ('aware_at', 'notified_at', 'final_at'))
        OR (regime = 'usom' AND instant IN
            ('aware_at', 'notified_at'))
    );

ALTER TABLE regulatory_report_drafts
    DROP CONSTRAINT IF EXISTS regulatory_report_drafts_kind_check;
ALTER TABLE regulatory_report_drafts
    ADD CONSTRAINT regulatory_report_drafts_kind_check CHECK (
        (regime = 'dora' AND kind IN ('initial', 'intermediate', 'final'))
        OR (regime = 'nis2' AND kind IN ('early_warning', 'notification', 'intermediate', 'final'))
        OR (regime = 'kvkk' AND kind IN ('board_notification'))
        OR (regime = 'bddk' AND kind IN ('notification', 'final'))
        OR (regime = 'usom' AND kind IN ('notification'))
    );
