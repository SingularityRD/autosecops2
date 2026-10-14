-- Vigil 0.7.1 database for the 0.7.1 -> 2.0 upgrade test (W4.5).
-- Source: upstream Vigil-SOC/vigil f72243c443eb72eb99a333f2da2d3f3aec9dc1e5 (release 0.7.1), provisioned as its
-- Compose stack did, seeded with tests/fixtures/upgrade/seed_0_7_1.sql.
-- Regenerate: python scripts/build_upgrade_fixture.py. Synthetic data only.
--
-- PostgreSQL database dump
--


-- Dumped from database version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: agent_event_hash(text, jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.agent_event_hash(prev_hash text, payload jsonb) RETURNS text
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'public'
    AS $$
  SELECT encode(
    sha256(convert_to(coalesce(prev_hash, '') || CAST(payload AS text), 'UTF8')),
    'hex'
  );
$$;


--
-- Name: agent_events_assign_hashes(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.agent_events_assign_hashes() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN
  SELECT event_hash INTO NEW.prev_hash
    FROM agent_events
    WHERE run_id = NEW.run_id AND seq < NEW.seq
    ORDER BY seq DESC
    LIMIT 1;
  NEW.prev_hash := coalesce(NEW.prev_hash, '');
  NEW.event_hash := agent_event_hash(NEW.prev_hash, NEW.payload);
  RETURN NEW;
END;
$$;


--
-- Name: update_ai_model_configs_timestamp(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_ai_model_configs_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_custom_agents_timestamp(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_custom_agents_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_integration_configs_timestamp(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_integration_configs_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_llm_provider_configs_timestamp(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_llm_provider_configs_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_system_config_timestamp(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_system_config_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_user_preferences_timestamp(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_user_preferences_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: agent_directives; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_directives (
    id bigint NOT NULL,
    run_id uuid NOT NULL,
    directive_id text NOT NULL,
    kind text NOT NULL,
    actor text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    payload jsonb NOT NULL
);


--
-- Name: agent_directives_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_directives_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_directives_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_directives_id_seq OWNED BY public.agent_directives.id;


--
-- Name: agent_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_events (
    run_id uuid NOT NULL,
    seq integer NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    run_kind text NOT NULL,
    kind text NOT NULL,
    payload jsonb NOT NULL,
    snapshot jsonb,
    schema_version integer NOT NULL,
    prev_hash text NOT NULL,
    event_hash text NOT NULL
);


--
-- Name: agent_run_leases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_run_leases (
    run_id uuid NOT NULL,
    run_kind text NOT NULL,
    owner text,
    claim_until timestamp with time zone NOT NULL
);


--
-- Name: ai_decision_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_decision_logs (
    id integer NOT NULL,
    decision_id character varying(50) NOT NULL,
    agent_id character varying(50) NOT NULL,
    workflow_id character varying(50),
    finding_id character varying(50),
    case_id character varying(50),
    decision_type character varying(50) NOT NULL,
    confidence_score double precision NOT NULL,
    reasoning text NOT NULL,
    recommended_action text NOT NULL,
    decision_metadata jsonb,
    human_reviewer character varying(100),
    human_decision character varying(50),
    feedback_comment text,
    accuracy_grade double precision,
    reasoning_grade double precision,
    action_appropriateness double precision,
    actual_outcome character varying(50),
    time_saved_minutes integer,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL,
    feedback_timestamp timestamp without time zone
);


--
-- Name: ai_decision_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ai_decision_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ai_decision_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ai_decision_logs_id_seq OWNED BY public.ai_decision_logs.id;


--
-- Name: ai_model_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_model_configs (
    component character varying(64) NOT NULL,
    provider_id character varying(64) NOT NULL,
    model_id character varying(200) NOT NULL,
    settings jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_by character varying(64),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: approval_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.approval_actions (
    action_id character varying(80) NOT NULL,
    action_type character varying(40) NOT NULL,
    title text NOT NULL,
    description text NOT NULL,
    target text NOT NULL,
    confidence numeric(4,3) DEFAULT 0 NOT NULL,
    reason text NOT NULL,
    evidence jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    created_by character varying(100) NOT NULL,
    requires_approval boolean DEFAULT true NOT NULL,
    status character varying(16) NOT NULL,
    approved_at timestamp without time zone,
    approved_by character varying(100),
    executed_at timestamp without time zone,
    execution_result jsonb,
    rejection_reason text,
    parameters jsonb DEFAULT '{}'::jsonb NOT NULL,
    workflow_run_id character varying(80),
    workflow_phase_id text,
    reversibility character varying(16) DEFAULT 'reversible'::character varying NOT NULL,
    idempotency_key text,
    CONSTRAINT approval_actions_reversibility_check CHECK (((reversibility)::text = ANY ((ARRAY['reversible'::character varying, 'irreversible'::character varying])::text[]))),
    CONSTRAINT approval_actions_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying, 'executed'::character varying, 'failed'::character varying])::text[])))
);


--
-- Name: case_attachments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_attachments (
    attachment_id integer NOT NULL,
    case_id character varying(50) NOT NULL,
    filename character varying(255) NOT NULL,
    file_path character varying(500) NOT NULL,
    file_type character varying(100),
    file_size integer NOT NULL,
    mime_type character varying(100),
    uploaded_by character varying(100) NOT NULL,
    description text,
    tags character varying[],
    virus_scan_result character varying(50),
    scan_details jsonb,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: case_attachments_attachment_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_attachments_attachment_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_attachments_attachment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_attachments_attachment_id_seq OWNED BY public.case_attachments.attachment_id;


--
-- Name: case_audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_audit_logs (
    audit_id integer NOT NULL,
    entity_type character varying(50) NOT NULL,
    entity_id character varying(100) NOT NULL,
    action character varying(20) NOT NULL,
    field_name character varying(100),
    old_value text,
    new_value text,
    change_summary text,
    changed_by character varying(100) NOT NULL,
    user_agent character varying(200),
    ip_address character varying(45),
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: case_audit_logs_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_audit_logs_audit_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_audit_logs_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_audit_logs_audit_id_seq OWNED BY public.case_audit_logs.audit_id;


--
-- Name: case_closure_info; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_closure_info (
    case_id character varying(50) NOT NULL,
    closure_category character varying(50) NOT NULL,
    root_cause text,
    contributing_factors character varying[],
    lessons_learned text,
    recommendations text,
    recurrence_prevention text,
    false_positive_reason text,
    executive_summary text,
    closed_by character varying(100) NOT NULL,
    closed_by_kind character varying(16) DEFAULT 'agent'::character varying NOT NULL,
    closure_notes text,
    closed_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT case_closure_info_closed_by_kind_check CHECK (((closed_by_kind)::text = ANY ((ARRAY['analyst'::character varying, 'agent'::character varying])::text[])))
);


--
-- Name: case_comments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_comments (
    comment_id integer NOT NULL,
    case_id character varying(50) NOT NULL,
    parent_comment_id integer,
    author character varying(100) NOT NULL,
    content text NOT NULL,
    mentions character varying[],
    attachment_ids integer[],
    is_edited boolean NOT NULL,
    is_deleted boolean NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: case_comments_comment_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_comments_comment_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_comments_comment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_comments_comment_id_seq OWNED BY public.case_comments.comment_id;


--
-- Name: case_escalations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_escalations (
    escalation_id integer NOT NULL,
    case_id character varying(50) NOT NULL,
    escalated_from character varying(100) NOT NULL,
    escalated_to character varying(100) NOT NULL,
    reason text NOT NULL,
    urgency_level character varying(20) NOT NULL,
    status character varying(20) NOT NULL,
    escalated_at timestamp without time zone DEFAULT now() NOT NULL,
    acknowledged_at timestamp without time zone,
    resolved_at timestamp without time zone,
    resolution_notes text
);


--
-- Name: case_escalations_escalation_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_escalations_escalation_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_escalations_escalation_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_escalations_escalation_id_seq OWNED BY public.case_escalations.escalation_id;


--
-- Name: case_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_evidence (
    evidence_id integer NOT NULL,
    case_id character varying(50) NOT NULL,
    evidence_type character varying(50) NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    file_path character varying(500),
    file_size integer,
    file_hash_md5 character varying(32),
    file_hash_sha256 character varying(64),
    source character varying(200),
    collected_by character varying(100) NOT NULL,
    collected_at timestamp without time zone NOT NULL,
    chain_of_custody jsonb NOT NULL,
    analysis_results jsonb,
    tags character varying[],
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: case_evidence_evidence_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_evidence_evidence_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_evidence_evidence_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_evidence_evidence_id_seq OWNED BY public.case_evidence.evidence_id;


--
-- Name: case_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_findings (
    case_id character varying NOT NULL,
    finding_id character varying NOT NULL,
    added_at timestamp without time zone NOT NULL
);


--
-- Name: case_iocs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_iocs (
    ioc_id integer NOT NULL,
    case_id character varying(50) NOT NULL,
    ioc_type character varying(50) NOT NULL,
    value character varying(500) NOT NULL,
    threat_level character varying(20),
    confidence double precision,
    source character varying(200),
    first_seen timestamp without time zone,
    last_seen timestamp without time zone,
    enrichment_data jsonb,
    reputation_score double precision,
    tags character varying[],
    context text,
    is_active boolean NOT NULL,
    is_false_positive boolean NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: case_iocs_ioc_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_iocs_ioc_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_iocs_ioc_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_iocs_ioc_id_seq OWNED BY public.case_iocs.ioc_id;


--
-- Name: case_metrics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_metrics (
    case_id character varying(50) NOT NULL,
    time_to_detect integer,
    time_to_respond integer,
    time_to_contain integer,
    time_to_resolve integer,
    total_work_hours double precision,
    analyst_handoffs_count integer NOT NULL,
    sla_met boolean,
    response_sla_met boolean,
    resolution_sla_met boolean,
    comment_count integer NOT NULL,
    evidence_count integer NOT NULL,
    ioc_count integer NOT NULL,
    task_count integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: case_notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_notifications (
    notification_id integer NOT NULL,
    case_id character varying(50),
    user_id character varying(100) NOT NULL,
    notification_type character varying(50) NOT NULL,
    title character varying(200) NOT NULL,
    message text NOT NULL,
    delivery_channel character varying(20) NOT NULL,
    priority character varying(20) NOT NULL,
    is_read boolean NOT NULL,
    is_sent boolean NOT NULL,
    sent_at timestamp without time zone,
    read_at timestamp without time zone,
    notification_metadata jsonb,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: case_notifications_notification_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_notifications_notification_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_notifications_notification_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_notifications_notification_id_seq OWNED BY public.case_notifications.notification_id;


--
-- Name: case_relationships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_relationships (
    relationship_id integer NOT NULL,
    case_id character varying(50) NOT NULL,
    related_case_id character varying(50) NOT NULL,
    relationship_type character varying(50) NOT NULL,
    created_by character varying(100) NOT NULL,
    notes text,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: case_relationships_relationship_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_relationships_relationship_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_relationships_relationship_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_relationships_relationship_id_seq OWNED BY public.case_relationships.relationship_id;


--
-- Name: case_slas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_slas (
    sla_id integer NOT NULL,
    case_id character varying(50) NOT NULL,
    sla_policy_id character varying(50) NOT NULL,
    response_due timestamp without time zone NOT NULL,
    resolution_due timestamp without time zone NOT NULL,
    response_completed_at timestamp without time zone,
    response_sla_met boolean,
    resolution_completed_at timestamp without time zone,
    resolution_sla_met boolean,
    breached boolean NOT NULL,
    breach_time timestamp without time zone,
    breach_reason text,
    is_paused boolean NOT NULL,
    paused_at timestamp without time zone,
    resumed_at timestamp without time zone,
    total_pause_duration integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: case_slas_sla_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_slas_sla_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_slas_sla_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_slas_sla_id_seq OWNED BY public.case_slas.sla_id;


--
-- Name: case_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_tasks (
    task_id integer NOT NULL,
    case_id character varying(50) NOT NULL,
    parent_task_id integer,
    title character varying(200) NOT NULL,
    description text,
    assignee character varying(100),
    status character varying(20) NOT NULL,
    priority character varying(20) NOT NULL,
    due_date timestamp without time zone,
    completed_at timestamp without time zone,
    estimated_hours double precision,
    actual_hours double precision,
    checklist_items jsonb,
    task_order integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: case_tasks_task_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_tasks_task_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_tasks_task_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_tasks_task_id_seq OWNED BY public.case_tasks.task_id;


--
-- Name: case_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_templates (
    template_id character varying(50) NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    template_type character varying(50) NOT NULL,
    default_priority character varying(20) NOT NULL,
    default_status character varying(20) NOT NULL,
    default_sla_policy_id character varying(50),
    task_templates jsonb NOT NULL,
    playbook_steps jsonb,
    applicable_mitre_techniques character varying[],
    tags character varying[],
    is_active boolean NOT NULL,
    usage_count integer DEFAULT 0 NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: case_watchers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_watchers (
    case_id character varying(50) NOT NULL,
    user_id character varying(100) NOT NULL,
    notification_preferences jsonb,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: cases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cases (
    case_id character varying(50) NOT NULL,
    title character varying(200) NOT NULL,
    description text,
    status character varying(20) DEFAULT 'new'::character varying NOT NULL,
    priority character varying(20) DEFAULT 'medium'::character varying NOT NULL,
    assignee character varying(100),
    tags character varying[],
    notes jsonb,
    timeline jsonb NOT NULL,
    activities jsonb,
    resolution_steps jsonb,
    mitre_techniques character varying[],
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_messages (
    id integer NOT NULL,
    conversation_id character varying(120) NOT NULL,
    seq integer NOT NULL,
    role character varying(20) NOT NULL,
    content text NOT NULL,
    thinking text,
    tool_calls jsonb NOT NULL,
    complete boolean DEFAULT true NOT NULL,
    model character varying(80),
    input_tokens integer DEFAULT 0 NOT NULL,
    output_tokens integer DEFAULT 0 NOT NULL,
    cost_usd numeric(10,6) DEFAULT '0'::numeric NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_messages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chat_messages_id_seq OWNED BY public.chat_messages.id;


--
-- Name: config_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.config_audit_log (
    id integer NOT NULL,
    config_type character varying(50) NOT NULL,
    config_key character varying(200) NOT NULL,
    action character varying(20) NOT NULL,
    old_value jsonb,
    new_value jsonb,
    changed_by character varying(100) NOT NULL,
    change_reason text,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: config_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.config_audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: config_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.config_audit_log_id_seq OWNED BY public.config_audit_log.id;


--
-- Name: conversations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conversations (
    id character varying(120) NOT NULL,
    user_id character varying(50),
    title character varying(200),
    case_id character varying(50),
    page_context character varying(120),
    agent_id character varying(60),
    model character varying(80),
    archived boolean DEFAULT false NOT NULL,
    message_count integer DEFAULT 0 NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    last_message_at timestamp without time zone
);


--
-- Name: custom_agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_agents (
    id text NOT NULL,
    name text NOT NULL,
    description text,
    icon text,
    color text,
    specialization text,
    role text NOT NULL,
    extra_principles text DEFAULT ''::text NOT NULL,
    methodology text DEFAULT ''::text NOT NULL,
    system_prompt_override text,
    recommended_tools jsonb DEFAULT '[]'::jsonb NOT NULL,
    max_tokens integer DEFAULT 4096 NOT NULL,
    enable_thinking boolean DEFAULT false NOT NULL,
    model text,
    forked_from text,
    created_by character varying(100),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    component_category character varying(32) DEFAULT 'investigation'::character varying NOT NULL,
    fallback_model text
);


--
-- Name: custom_workflows; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_workflows (
    workflow_id character varying(100) NOT NULL,
    name character varying(200) NOT NULL,
    description text NOT NULL,
    use_case text,
    trigger_examples jsonb DEFAULT '[]'::jsonb NOT NULL,
    phases jsonb DEFAULT '[]'::jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_by character varying(100),
    version integer DEFAULT 1 NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: integration_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_configs (
    integration_id character varying(100) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    integration_name character varying(200),
    integration_type character varying(50),
    description text,
    last_test_at timestamp without time zone,
    last_test_success boolean,
    last_error text,
    updated_by character varying(100),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: enabled_integrations; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.enabled_integrations AS
 SELECT integration_id,
    integration_name,
    integration_type,
    config,
    last_test_at,
    last_test_success,
    updated_at
   FROM public.integration_configs
  WHERE (enabled = true)
  ORDER BY integration_name;


--
-- Name: episodic_distil_failures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.episodic_distil_failures (
    investigation_kind text NOT NULL,
    failure_key text NOT NULL,
    origin_seq integer,
    reason text NOT NULL,
    attempts integer NOT NULL,
    last_error text NOT NULL,
    first_failed_at timestamp with time zone NOT NULL,
    last_failed_at timestamp with time zone NOT NULL,
    next_attempt_at timestamp with time zone NOT NULL,
    distil_version integer NOT NULL,
    CONSTRAINT episodic_distil_failures_attempts_check CHECK ((attempts > 0)),
    CONSTRAINT episodic_distil_failures_investigation_kind_check CHECK ((investigation_kind = ANY (ARRAY['hunt'::text, 'case'::text, 'analyst'::text]))),
    CONSTRAINT episodic_distil_failures_reason_check CHECK ((reason = ANY (ARRAY['refused'::text, 'unreadable'::text, 'failed'::text]))),
    CONSTRAINT episodic_distil_failures_seq_matches_kind CHECK (((investigation_kind = 'hunt'::text) = (origin_seq IS NOT NULL))),
    CONSTRAINT episodic_distil_failures_window CHECK ((first_failed_at <= last_failed_at))
);


--
-- Name: episodic_distil_markers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.episodic_distil_markers (
    investigation_kind text NOT NULL,
    investigation_id text NOT NULL,
    origin_run_id uuid,
    origin_seq integer,
    origin_run_ids uuid[] DEFAULT ARRAY[]::uuid[] NOT NULL,
    distil_version integer NOT NULL,
    sightings_written integer NOT NULL,
    verdicts_written integer NOT NULL,
    gaps_written integer NOT NULL,
    concluded_at timestamp with time zone NOT NULL,
    distilled_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT episodic_distil_markers_gaps_written_check CHECK ((gaps_written >= 0)),
    CONSTRAINT episodic_distil_markers_investigation_kind_check CHECK ((investigation_kind = ANY (ARRAY['hunt'::text, 'case'::text, 'analyst'::text]))),
    CONSTRAINT episodic_distil_markers_origin_matches_kind CHECK ((((investigation_kind = 'hunt'::text) = (origin_run_id IS NOT NULL)) AND ((origin_run_id IS NULL) = (origin_seq IS NULL)))),
    CONSTRAINT episodic_distil_markers_sightings_written_check CHECK ((sightings_written >= 0)),
    CONSTRAINT episodic_distil_markers_verdicts_written_check CHECK ((verdicts_written >= 0))
);


--
-- Name: episodic_gaps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.episodic_gaps (
    id bigint NOT NULL,
    investigation_kind text NOT NULL,
    investigation_id text NOT NULL,
    hypothesis_id text NOT NULL,
    statement text NOT NULL,
    disposition text NOT NULL,
    reason text NOT NULL,
    subject_entities text[] DEFAULT ARRAY[]::text[] NOT NULL,
    concluded_at timestamp with time zone NOT NULL,
    CONSTRAINT episodic_gaps_disposition_check CHECK ((disposition = ANY (ARRAY['deprioritised'::text, 'no_evidence_gathered'::text, 'budget_exhausted'::text]))),
    CONSTRAINT episodic_gaps_investigation_kind_check CHECK ((investigation_kind = ANY (ARRAY['hunt'::text, 'case'::text, 'analyst'::text])))
);


--
-- Name: episodic_gaps_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.episodic_gaps_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: episodic_gaps_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.episodic_gaps_id_seq OWNED BY public.episodic_gaps.id;


--
-- Name: episodic_read_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.episodic_read_log (
    id bigint NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    caller_kind text DEFAULT 'unknown'::text NOT NULL,
    caller_id text DEFAULT 'unknown'::text NOT NULL,
    keys text[] NOT NULL,
    as_of timestamp with time zone NOT NULL,
    row_counts jsonb NOT NULL,
    dropped jsonb NOT NULL,
    ranking jsonb NOT NULL
);


--
-- Name: episodic_read_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.episodic_read_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: episodic_read_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.episodic_read_log_id_seq OWNED BY public.episodic_read_log.id;


--
-- Name: episodic_sightings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.episodic_sightings (
    id bigint NOT NULL,
    entity_key text NOT NULL,
    investigation_kind text NOT NULL,
    investigation_id text NOT NULL,
    source_system text NOT NULL,
    hit_count integer NOT NULL,
    attacker_influenceable boolean NOT NULL,
    first_seen timestamp with time zone NOT NULL,
    last_seen timestamp with time zone NOT NULL,
    concluded_at timestamp with time zone NOT NULL,
    CONSTRAINT episodic_sightings_hit_count_check CHECK ((hit_count > 0)),
    CONSTRAINT episodic_sightings_investigation_kind_check CHECK ((investigation_kind = ANY (ARRAY['hunt'::text, 'case'::text, 'analyst'::text]))),
    CONSTRAINT episodic_sightings_window CHECK ((first_seen <= last_seen))
);


--
-- Name: episodic_sightings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.episodic_sightings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: episodic_sightings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.episodic_sightings_id_seq OWNED BY public.episodic_sightings.id;


--
-- Name: episodic_verdict_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.episodic_verdict_sources (
    id bigint NOT NULL,
    verdict_id bigint NOT NULL,
    source_system text NOT NULL,
    stance text NOT NULL,
    source_tier text NOT NULL,
    CONSTRAINT episodic_verdict_sources_source_tier_check CHECK ((source_tier = ANY (ARRAY['telemetry'::text, 'feed'::text, 'not_evidence'::text]))),
    CONSTRAINT episodic_verdict_sources_stance_check CHECK ((stance = ANY (ARRAY['supports'::text, 'weakens'::text, 'neither'::text])))
);


--
-- Name: episodic_verdict_sources_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.episodic_verdict_sources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: episodic_verdict_sources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.episodic_verdict_sources_id_seq OWNED BY public.episodic_verdict_sources.id;


--
-- Name: episodic_verdicts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.episodic_verdicts (
    id bigint NOT NULL,
    investigation_kind text NOT NULL,
    investigation_id text NOT NULL,
    hypothesis_id text NOT NULL,
    statement text NOT NULL,
    outcome text NOT NULL,
    rationale text NOT NULL,
    subject_entities text[] DEFAULT ARRAY[]::text[] NOT NULL,
    attacker_influenceable_only boolean NOT NULL,
    trust text NOT NULL,
    first_seen timestamp with time zone NOT NULL,
    last_seen timestamp with time zone NOT NULL,
    window_source text NOT NULL,
    concluded_at timestamp with time zone NOT NULL,
    techniques text[] DEFAULT ARRAY[]::text[] NOT NULL,
    CONSTRAINT episodic_verdicts_investigation_kind_check CHECK ((investigation_kind = ANY (ARRAY['hunt'::text, 'case'::text, 'analyst'::text]))),
    CONSTRAINT episodic_verdicts_outcome_check CHECK ((outcome = ANY (ARRAY['proven'::text, 'disproven'::text, 'inconclusive'::text, 'handed_off'::text, 'false_positive'::text]))),
    CONSTRAINT episodic_verdicts_trust_check CHECK ((trust = ANY (ARRAY['analyst'::text, 'agent'::text]))),
    CONSTRAINT episodic_verdicts_window CHECK ((first_seen <= last_seen)),
    CONSTRAINT episodic_verdicts_window_source_check CHECK ((window_source = ANY (ARRAY['observed'::text, 'asserted'::text])))
);


--
-- Name: episodic_verdicts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.episodic_verdicts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: episodic_verdicts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.episodic_verdicts_id_seq OWNED BY public.episodic_verdicts.id;


--
-- Name: federation_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_sources (
    source_id character varying(64) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    interval_seconds integer DEFAULT 300 NOT NULL,
    max_items integer DEFAULT 100 NOT NULL,
    min_severity character varying(16),
    cursor jsonb DEFAULT '{}'::jsonb NOT NULL,
    last_poll_at timestamp with time zone,
    last_success_at timestamp with time zone,
    last_error text,
    consecutive_errors integer DEFAULT 0 NOT NULL,
    dropped_total integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: finding_mitre_predictions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_mitre_predictions (
    finding_id character varying(50) NOT NULL,
    technique_id text NOT NULL,
    confidence double precision NOT NULL
);


--
-- Name: findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.findings (
    finding_id character varying(50) NOT NULL,
    anomaly_score double precision,
    title text,
    description text,
    entity_context jsonb,
    evidence_links jsonb,
    "timestamp" timestamp without time zone,
    data_source character varying(50) NOT NULL,
    external_id character varying(255),
    cluster_id character varying(50),
    severity character varying(20),
    status character varying(20) DEFAULT 'new'::character varying NOT NULL,
    noise_marked_at timestamp without time zone,
    noise_marked_by character varying(50),
    ai_enrichment jsonb,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: intake_triggers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.intake_triggers (
    id integer NOT NULL,
    kind character varying(20) NOT NULL,
    state character varying(20) NOT NULL,
    reason text,
    finding_id character varying(50),
    priority character varying(20) NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    investigation_id character varying(60),
    case_id character varying(50),
    merged_into character varying(60),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    decided_at timestamp without time zone
);


--
-- Name: intake_triggers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.intake_triggers_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: intake_triggers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.intake_triggers_id_seq OWNED BY public.intake_triggers.id;


--
-- Name: investigation_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_logs (
    id integer NOT NULL,
    investigation_id character varying(60) NOT NULL,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL,
    event_type character varying(30) NOT NULL,
    details jsonb NOT NULL,
    tokens_used integer NOT NULL
);


--
-- Name: investigation_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.investigation_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: investigation_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.investigation_logs_id_seq OWNED BY public.investigation_logs.id;


--
-- Name: investigations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigations (
    investigation_id character varying(60) NOT NULL,
    case_id character varying(50),
    workflow_id character varying(50) NOT NULL,
    trigger_type character varying(30) NOT NULL,
    trigger_ids jsonb NOT NULL,
    status character varying(20) NOT NULL,
    workdir character varying(255) NOT NULL,
    current_step integer NOT NULL,
    total_steps integer NOT NULL,
    iteration_count integer NOT NULL,
    max_iterations integer NOT NULL,
    input_tokens integer NOT NULL,
    output_tokens integer NOT NULL,
    cost_usd double precision NOT NULL,
    max_cost_usd double precision NOT NULL,
    priority character varying(20) NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    last_activity_at timestamp without time zone,
    max_runtime_seconds integer NOT NULL,
    summary text,
    proposed_actions jsonb,
    master_review_notes text,
    error_count integer NOT NULL,
    last_error text,
    current_activity text
);


--
-- Name: ip_exclusions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ip_exclusions (
    exclusion_id character varying(50) NOT NULL,
    ip character varying(45) NOT NULL,
    reason text NOT NULL,
    origin character varying(20) DEFAULT 'ad_hoc'::character varying NOT NULL,
    origin_ref character varying(100),
    created_by character varying(100) NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    removed_at timestamp without time zone,
    removed_by character varying(100),
    removal_reason text,
    CONSTRAINT ck_ip_exclusions_origin CHECK (((origin)::text = ANY ((ARRAY['ad_hoc'::character varying, 'finding'::character varying, 'case'::character varying, 'run'::character varying])::text[]))),
    CONSTRAINT ck_ip_exclusions_removal CHECK (((removed_at IS NULL) = (removed_by IS NULL)))
);


--
-- Name: llm_interaction_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_interaction_logs (
    id integer NOT NULL,
    interaction_id character varying(60) NOT NULL,
    session_id character varying(120),
    agent_id character varying(60),
    investigation_id character varying(60),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    model character varying(80) NOT NULL,
    request_messages jsonb NOT NULL,
    system_prompt text,
    thinking_enabled boolean NOT NULL,
    thinking_budget integer,
    thinking_content text,
    response_content text,
    tool_calls jsonb NOT NULL,
    tool_results jsonb NOT NULL,
    stop_reason character varying(40),
    input_tokens integer NOT NULL,
    output_tokens integer NOT NULL,
    cache_read_tokens integer NOT NULL,
    cache_creation_tokens integer NOT NULL,
    cost_usd numeric(10,6),
    input_cost_per_token double precision,
    output_cost_per_token double precision,
    cache_read_cost_per_token double precision,
    cache_write_cost_per_token double precision,
    rates_fetched_at character varying(64),
    duration_ms integer NOT NULL,
    error text,
    virtual_key_id character varying(64)
);


--
-- Name: llm_interaction_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.llm_interaction_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: llm_interaction_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.llm_interaction_logs_id_seq OWNED BY public.llm_interaction_logs.id;


--
-- Name: llm_provider_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_provider_configs (
    provider_id character varying(64) NOT NULL,
    provider_type character varying(32) NOT NULL,
    name character varying(200) NOT NULL,
    base_url character varying(500),
    api_key_ref character varying(200),
    default_model character varying(200) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    last_test_at timestamp without time zone,
    last_test_success boolean,
    last_error text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: mcp_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_credentials (
    credential_id character varying(50) NOT NULL,
    user_id character varying(50) NOT NULL,
    token_hash character(64) NOT NULL,
    label character varying(200) NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    last_used_at timestamp without time zone,
    expires_at timestamp without time zone,
    revoked_at timestamp without time zone
);


--
-- Name: recent_config_changes; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.recent_config_changes AS
 SELECT config_type,
    config_key,
    action,
    changed_by,
    "timestamp",
    change_reason
   FROM public.config_audit_log
  ORDER BY "timestamp" DESC
 LIMIT 100;


--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
    role_id character varying(50) NOT NULL,
    name character varying(100) NOT NULL,
    description text NOT NULL,
    permissions jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_system_role boolean DEFAULT false NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: shared_iocs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shared_iocs (
    id integer NOT NULL,
    investigation_id character varying(60) NOT NULL,
    ioc_type character varying(30) NOT NULL,
    value character varying(500) NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: shared_iocs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.shared_iocs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: shared_iocs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.shared_iocs_id_seq OWNED BY public.shared_iocs.id;


--
-- Name: sketch_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sketch_mappings (
    id integer NOT NULL,
    case_id character varying(50),
    finding_id character varying(50),
    sketch_id integer NOT NULL,
    sketch_name character varying(200) NOT NULL,
    sketch_url character varying(500),
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: sketch_mappings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sketch_mappings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sketch_mappings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sketch_mappings_id_seq OWNED BY public.sketch_mappings.id;


--
-- Name: sla_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sla_policies (
    policy_id character varying(50) NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    priority_level character varying(20) NOT NULL,
    response_time_hours double precision NOT NULL,
    resolution_time_hours double precision NOT NULL,
    business_hours_only boolean NOT NULL,
    escalation_rules jsonb,
    notification_thresholds integer[],
    is_active boolean NOT NULL,
    is_default boolean NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: system_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_config (
    key character varying(100) NOT NULL,
    value jsonb NOT NULL,
    description text,
    config_type character varying(50) DEFAULT 'general'::character varying NOT NULL,
    updated_by character varying(100),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: threat_indicators; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_indicators (
    id bigint NOT NULL,
    indicator_type character varying(32) NOT NULL,
    indicator_value character varying(2048) NOT NULL,
    source character varying(64) NOT NULL,
    collection_id character varying(128),
    confidence numeric(5,2),
    threat_level character varying(16),
    labels text[] DEFAULT ARRAY[]::text[],
    valid_from timestamp without time zone,
    valid_until timestamp without time zone,
    raw_stix jsonb,
    first_seen timestamp without time zone DEFAULT now() NOT NULL,
    last_seen timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: threat_indicators_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_indicators_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_indicators_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_indicators_id_seq OWNED BY public.threat_indicators.id;


--
-- Name: user_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_preferences (
    user_id character varying(100) NOT NULL,
    preferences jsonb DEFAULT '{}'::jsonb NOT NULL,
    display_name character varying(200),
    email character varying(200),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    last_login timestamp without time zone
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    user_id character varying(50) NOT NULL,
    username character varying(100) NOT NULL,
    email character varying(200) NOT NULL,
    password_hash character varying(255) NOT NULL,
    full_name character varying(200) NOT NULL,
    role_id character varying(50) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    is_verified boolean DEFAULT false NOT NULL,
    mfa_enabled boolean DEFAULT false NOT NULL,
    mfa_secret character varying(255),
    mfa_recovery_codes jsonb DEFAULT '[]'::jsonb NOT NULL,
    last_login timestamp without time zone,
    login_count integer DEFAULT 0 NOT NULL,
    failed_login_count integer DEFAULT 0 NOT NULL,
    locked_until timestamp without time zone,
    password_history jsonb DEFAULT '[]'::jsonb NOT NULL,
    password_changed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: workflow_run_phases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_run_phases (
    run_id character varying(80) NOT NULL,
    phase_id text NOT NULL,
    phase_order integer NOT NULL,
    agent_id text NOT NULL,
    status character varying(16) NOT NULL,
    started_at timestamp without time zone,
    finished_at timestamp without time zone,
    duration_ms integer,
    input_context jsonb DEFAULT '{}'::jsonb NOT NULL,
    output jsonb DEFAULT '{}'::jsonb NOT NULL,
    approval_state character varying(16),
    cost_usd numeric(10,4) DEFAULT 0 NOT NULL,
    error text,
    CONSTRAINT workflow_run_phases_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'completed'::character varying, 'failed'::character varying, 'skipped'::character varying, 'pending_approval'::character varying])::text[])))
);


--
-- Name: workflow_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_runs (
    run_id character varying(80) NOT NULL,
    workflow_id text NOT NULL,
    workflow_version integer,
    workflow_source character varying(16) DEFAULT 'file'::character varying NOT NULL,
    workflow_name text NOT NULL,
    status character varying(16) NOT NULL,
    triggered_by character varying(100),
    trigger_context jsonb DEFAULT '{}'::jsonb NOT NULL,
    started_at timestamp without time zone DEFAULT now() NOT NULL,
    finished_at timestamp without time zone,
    duration_ms integer,
    total_cost_usd numeric(10,4) DEFAULT 0 NOT NULL,
    result_summary text,
    error text,
    deleted_at timestamp without time zone,
    outcome text,
    reason text,
    CONSTRAINT workflow_runs_status_check CHECK (((status)::text = ANY ((ARRAY['running'::character varying, 'paused'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[])))
);


--
-- Name: agent_directives id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_directives ALTER COLUMN id SET DEFAULT nextval('public.agent_directives_id_seq'::regclass);


--
-- Name: ai_decision_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_decision_logs ALTER COLUMN id SET DEFAULT nextval('public.ai_decision_logs_id_seq'::regclass);


--
-- Name: case_attachments attachment_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_attachments ALTER COLUMN attachment_id SET DEFAULT nextval('public.case_attachments_attachment_id_seq'::regclass);


--
-- Name: case_audit_logs audit_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_audit_logs ALTER COLUMN audit_id SET DEFAULT nextval('public.case_audit_logs_audit_id_seq'::regclass);


--
-- Name: case_comments comment_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_comments ALTER COLUMN comment_id SET DEFAULT nextval('public.case_comments_comment_id_seq'::regclass);


--
-- Name: case_escalations escalation_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_escalations ALTER COLUMN escalation_id SET DEFAULT nextval('public.case_escalations_escalation_id_seq'::regclass);


--
-- Name: case_evidence evidence_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_evidence ALTER COLUMN evidence_id SET DEFAULT nextval('public.case_evidence_evidence_id_seq'::regclass);


--
-- Name: case_iocs ioc_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_iocs ALTER COLUMN ioc_id SET DEFAULT nextval('public.case_iocs_ioc_id_seq'::regclass);


--
-- Name: case_notifications notification_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_notifications ALTER COLUMN notification_id SET DEFAULT nextval('public.case_notifications_notification_id_seq'::regclass);


--
-- Name: case_relationships relationship_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_relationships ALTER COLUMN relationship_id SET DEFAULT nextval('public.case_relationships_relationship_id_seq'::regclass);


--
-- Name: case_slas sla_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_slas ALTER COLUMN sla_id SET DEFAULT nextval('public.case_slas_sla_id_seq'::regclass);


--
-- Name: case_tasks task_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_tasks ALTER COLUMN task_id SET DEFAULT nextval('public.case_tasks_task_id_seq'::regclass);


--
-- Name: chat_messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages ALTER COLUMN id SET DEFAULT nextval('public.chat_messages_id_seq'::regclass);


--
-- Name: config_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.config_audit_log ALTER COLUMN id SET DEFAULT nextval('public.config_audit_log_id_seq'::regclass);


--
-- Name: episodic_gaps id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_gaps ALTER COLUMN id SET DEFAULT nextval('public.episodic_gaps_id_seq'::regclass);


--
-- Name: episodic_read_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_read_log ALTER COLUMN id SET DEFAULT nextval('public.episodic_read_log_id_seq'::regclass);


--
-- Name: episodic_sightings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_sightings ALTER COLUMN id SET DEFAULT nextval('public.episodic_sightings_id_seq'::regclass);


--
-- Name: episodic_verdict_sources id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_verdict_sources ALTER COLUMN id SET DEFAULT nextval('public.episodic_verdict_sources_id_seq'::regclass);


--
-- Name: episodic_verdicts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_verdicts ALTER COLUMN id SET DEFAULT nextval('public.episodic_verdicts_id_seq'::regclass);


--
-- Name: intake_triggers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_triggers ALTER COLUMN id SET DEFAULT nextval('public.intake_triggers_id_seq'::regclass);


--
-- Name: investigation_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_logs ALTER COLUMN id SET DEFAULT nextval('public.investigation_logs_id_seq'::regclass);


--
-- Name: llm_interaction_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_interaction_logs ALTER COLUMN id SET DEFAULT nextval('public.llm_interaction_logs_id_seq'::regclass);


--
-- Name: shared_iocs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_iocs ALTER COLUMN id SET DEFAULT nextval('public.shared_iocs_id_seq'::regclass);


--
-- Name: sketch_mappings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sketch_mappings ALTER COLUMN id SET DEFAULT nextval('public.sketch_mappings_id_seq'::regclass);


--
-- Name: threat_indicators id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_indicators ALTER COLUMN id SET DEFAULT nextval('public.threat_indicators_id_seq'::regclass);


--
-- Data for Name: agent_directives; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.agent_directives (id, run_id, directive_id, kind, actor, created_at, payload) FROM stdin;
\.


--
-- Data for Name: agent_events; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.agent_events (run_id, seq, ts, run_kind, kind, payload, snapshot, schema_version, prev_hash, event_hash) FROM stdin;
5f0c4a52-6d2e-4f43-9a63-0a0000000001	1	2026-10-01 10:06:00+00	triage	run_started	{"finding_id": "f-upg-0001"}	\N	1		cb402f64395c93c7d8fe2998ea2b6836b7f2b8d7a5b597996cf861e00b342145
5f0c4a52-6d2e-4f43-9a63-0a0000000001	2	2026-10-01 10:06:30+00	triage	tool_call	{"args": {"ip": "192.0.2.10"}, "tool": "lookup_ip"}	\N	1	cb402f64395c93c7d8fe2998ea2b6836b7f2b8d7a5b597996cf861e00b342145	78ab5a48caf34bb88d89fd7875a366e7874cdcef6aaa28927b404bad7d9df375
5f0c4a52-6d2e-4f43-9a63-0a0000000001	3	2026-10-01 10:07:00+00	triage	run_finished	{"verdict": "malicious"}	{"verdict": "malicious"}	1	78ab5a48caf34bb88d89fd7875a366e7874cdcef6aaa28927b404bad7d9df375	f2d0e0c6c774f8d80d133afbf9b3ffab7c13031fb23ef752f37680bc449ab9a2
\.


--
-- Data for Name: agent_run_leases; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.agent_run_leases (run_id, run_kind, owner, claim_until) FROM stdin;
\.


--
-- Data for Name: ai_decision_logs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.ai_decision_logs (id, decision_id, agent_id, workflow_id, finding_id, case_id, decision_type, confidence_score, reasoning, recommended_action, decision_metadata, human_reviewer, human_decision, feedback_comment, accuracy_grade, reasoning_grade, action_appropriateness, actual_outcome, time_saved_minutes, "timestamp", feedback_timestamp) FROM stdin;
\.


--
-- Data for Name: ai_model_configs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.ai_model_configs (component, provider_id, model_id, settings, updated_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: approval_actions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.approval_actions (action_id, action_type, title, description, target, confidence, reason, evidence, created_at, created_by, requires_approval, status, approved_at, approved_by, executed_at, execution_result, rejection_reason, parameters, workflow_run_id, workflow_phase_id, reversibility, idempotency_key) FROM stdin;
act-upg-0001	block_ip	Block 192.0.2.10	Edge block	192.0.2.10	0.900	Brute force	["f-upg-0001"]	2026-10-01 10:10:00	agent	t	executed	2026-10-01 10:12:00	upg.admin	2026-10-01 10:12:05	{"message": "blocked"}	\N	{}	\N	\N	reversible	block_ip:192.0.2.10
act-upg-0002	isolate_host	Isolate ws-upg-01	Containment	ws-upg-01.example.com	0.700	Suspicious PowerShell	["f-upg-0002"]	2026-10-01 11:10:00	agent	t	executed	2026-10-01 11:12:00	upg.admin	2026-10-01 11:12:05	{"message": "Host isolated (MOCK)"}	\N	{}	\N	\N	reversible	isolate_host:ws-upg-01.example.com
act-upg-0003	disable_user	Disable upg.analyst	Pending review	upg.analyst	0.400	Low confidence	[]	2026-10-01 12:00:00	agent	t	pending	\N	\N	\N	\N	\N	{}	\N	\N	reversible	\N
\.


--
-- Data for Name: case_attachments; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_attachments (attachment_id, case_id, filename, file_path, file_type, file_size, mime_type, uploaded_by, description, tags, virus_scan_result, scan_details, created_at) FROM stdin;
\.


--
-- Data for Name: case_audit_logs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_audit_logs (audit_id, entity_type, entity_id, action, field_name, old_value, new_value, change_summary, changed_by, user_agent, ip_address, "timestamp") FROM stdin;
\.


--
-- Data for Name: case_closure_info; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_closure_info (case_id, closure_category, root_cause, contributing_factors, lessons_learned, recommendations, recurrence_prevention, false_positive_reason, executive_summary, closed_by, closed_by_kind, closure_notes, closed_at) FROM stdin;
\.


--
-- Data for Name: case_comments; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_comments (comment_id, case_id, parent_comment_id, author, content, mentions, attachment_ids, is_edited, is_deleted, created_at, updated_at) FROM stdin;
1	case-upg-0001	\N	upg.analyst	Source IP blocked at the edge; watching for retries.	\N	\N	f	f	2026-10-01 10:20:00	2026-10-01 10:20:00
\.


--
-- Data for Name: case_escalations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_escalations (escalation_id, case_id, escalated_from, escalated_to, reason, urgency_level, status, escalated_at, acknowledged_at, resolved_at, resolution_notes) FROM stdin;
\.


--
-- Data for Name: case_evidence; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_evidence (evidence_id, case_id, evidence_type, name, description, file_path, file_size, file_hash_md5, file_hash_sha256, source, collected_by, collected_at, chain_of_custody, analysis_results, tags, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: case_findings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_findings (case_id, finding_id, added_at) FROM stdin;
case-upg-0001	f-upg-0001	2026-10-01 10:05:00
case-upg-0001	f-upg-0002	2026-10-01 11:05:00
case-upg-0002	f-upg-0004	2026-10-02 12:10:00
\.


--
-- Data for Name: case_iocs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_iocs (ioc_id, case_id, ioc_type, value, threat_level, confidence, source, first_seen, last_seen, enrichment_data, reputation_score, tags, context, is_active, is_false_positive, created_at, updated_at) FROM stdin;
1	case-upg-0001	ip	192.0.2.10	high	0.9	analyst	\N	\N	\N	\N	\N	\N	t	f	2026-10-01 10:21:00	2026-10-01 10:21:00
\.


--
-- Data for Name: case_metrics; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_metrics (case_id, time_to_detect, time_to_respond, time_to_contain, time_to_resolve, total_work_hours, analyst_handoffs_count, sla_met, response_sla_met, resolution_sla_met, comment_count, evidence_count, ioc_count, task_count, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: case_notifications; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_notifications (notification_id, case_id, user_id, notification_type, title, message, delivery_channel, priority, is_read, is_sent, sent_at, read_at, notification_metadata, created_at) FROM stdin;
\.


--
-- Data for Name: case_relationships; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_relationships (relationship_id, case_id, related_case_id, relationship_type, created_by, notes, created_at) FROM stdin;
\.


--
-- Data for Name: case_slas; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_slas (sla_id, case_id, sla_policy_id, response_due, resolution_due, response_completed_at, response_sla_met, resolution_completed_at, resolution_sla_met, breached, breach_time, breach_reason, is_paused, paused_at, resumed_at, total_pause_duration, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: case_tasks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_tasks (task_id, case_id, parent_task_id, title, description, assignee, status, priority, due_date, completed_at, estimated_hours, actual_hours, checklist_items, task_order, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: case_templates; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_templates (template_id, name, description, template_type, default_priority, default_status, default_sla_policy_id, task_templates, playbook_steps, applicable_mitre_techniques, tags, is_active, usage_count, created_at, updated_at) FROM stdin;
template-malware-001	Malware Investigation	Standard template for investigating malware incidents	malware	high	open	sla-high-default	[{"order": 1, "title": "Initial Triage", "priority": "high", "description": "Assess malware type and scope"}, {"order": 2, "title": "Isolate Affected Systems", "priority": "critical", "description": "Contain the malware spread"}, {"order": 3, "title": "Collect Evidence", "priority": "high", "description": "Gather malware samples, logs, and artifacts"}, {"order": 4, "title": "Analyze Malware", "priority": "medium", "description": "Perform static and dynamic analysis"}, {"order": 5, "title": "Extract IOCs", "priority": "medium", "description": "Identify indicators of compromise"}, {"order": 6, "title": "Threat Hunting", "priority": "high", "description": "Hunt for additional compromised systems"}, {"order": 7, "title": "Remediation", "priority": "high", "description": "Remove malware and restore systems"}, {"order": 8, "title": "Post-Incident Review", "priority": "low", "description": "Document lessons learned"}]	[{"name": "Identify Malware Type", "step": 1, "actions": ["Review AV alerts", "Analyze file properties"]}, {"name": "Containment", "step": 2, "actions": ["Network isolation", "Disable user accounts"]}, {"name": "Eradication", "step": 3, "actions": ["Remove malware", "Patch vulnerabilities"]}, {"name": "Recovery", "step": 4, "actions": ["Restore from backup", "Monitor for reinfection"]}]	{T1059,T1055,T1486,T1566}	{malware,incident-response}	t	0	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
template-phishing-001	Phishing Investigation	Standard template for investigating phishing attacks	phishing	medium	open	sla-medium-default	[{"order": 1, "title": "Verify Phishing Report", "priority": "high", "description": "Confirm the email is malicious"}, {"order": 2, "title": "Identify Affected Users", "priority": "high", "description": "Find who received the phishing email"}, {"order": 3, "title": "Analyze Email", "priority": "medium", "description": "Extract headers, links, and attachments"}, {"order": 4, "title": "Block IOCs", "priority": "high", "description": "Block malicious URLs, domains, and IPs"}, {"order": 5, "title": "Search for Compromised Accounts", "priority": "high", "description": "Check for successful credential theft"}, {"order": 6, "title": "User Education", "priority": "medium", "description": "Notify and educate affected users"}, {"order": 7, "title": "Update Email Filters", "priority": "low", "description": "Add rules to prevent similar attacks"}]	[{"name": "Triage", "step": 1, "actions": ["Review email headers", "Check sender reputation"]}, {"name": "Containment", "step": 2, "actions": ["Delete emails from inboxes", "Block sender domain"]}, {"name": "Investigation", "step": 3, "actions": ["Analyze attachments/links", "Check for credential use"]}, {"name": "Communication", "step": 4, "actions": ["Alert users", "Security awareness reminder"]}]	{T1566.001,T1566.002,T1204}	{phishing,email-security}	t	0	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
template-data-exfiltration-001	Data Exfiltration Investigation	Template for investigating potential data exfiltration	data_exfiltration	critical	open	sla-critical-default	[{"order": 1, "title": "Identify Data Scope", "priority": "critical", "description": "Determine what data was accessed/exfiltrated"}, {"order": 2, "title": "Identify Threat Actor", "priority": "high", "description": "Determine who performed the exfiltration"}, {"order": 3, "title": "Block Exfiltration Channels", "priority": "critical", "description": "Prevent further data loss"}, {"order": 4, "title": "Preserve Evidence", "priority": "high", "description": "Collect logs, network captures, and artifacts"}, {"order": 5, "title": "Assess Impact", "priority": "high", "description": "Evaluate business and legal impact"}, {"order": 6, "title": "Legal/Compliance Notification", "priority": "critical", "description": "Notify legal team and regulators if required"}, {"order": 7, "title": "Containment", "priority": "high", "description": "Revoke access, rotate credentials"}, {"order": 8, "title": "Forensic Analysis", "priority": "medium", "description": "Deep dive investigation"}]	[{"name": "Detection", "step": 1, "actions": ["Review DLP alerts", "Analyze network traffic"]}, {"name": "Containment", "step": 2, "actions": ["Block C2 communications", "Isolate affected systems"]}, {"name": "Investigation", "step": 3, "actions": ["Timeline reconstruction", "Identify attack vector"]}, {"name": "Recovery", "step": 4, "actions": ["Restore access controls", "Implement monitoring"]}]	{T1048,T1041,T1567,T1020}	{data-breach,exfiltration,critical}	t	0	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
template-insider-threat-001	Insider Threat Investigation	Template for investigating insider threat activities	insider_threat	high	open	sla-high-default	[{"order": 1, "title": "Initial Assessment", "priority": "high", "description": "Review alert and user activity"}, {"order": 2, "title": "Preserve Evidence", "priority": "critical", "description": "Collect user activity logs and data"}, {"order": 3, "title": "Coordinate with HR/Legal", "priority": "high", "description": "Involve HR and legal team"}, {"order": 4, "title": "Analyze User Behavior", "priority": "high", "description": "Review access patterns and anomalies"}, {"order": 5, "title": "Assess Risk", "priority": "high", "description": "Determine potential damage and intent"}, {"order": 6, "title": "Containment Actions", "priority": "medium", "description": "Restrict access if necessary"}, {"order": 7, "title": "Interview Preparation", "priority": "medium", "description": "Prepare evidence for user interview"}, {"order": 8, "title": "Remediation", "priority": "low", "description": "Implement controls to prevent recurrence"}]	[{"name": "Detection", "step": 1, "actions": ["UEBA alert review", "Access log analysis"]}, {"name": "Evidence Collection", "step": 2, "actions": ["Covert monitoring", "Endpoint forensics"]}, {"name": "Coordination", "step": 3, "actions": ["HR notification", "Legal consultation"]}, {"name": "Action", "step": 4, "actions": ["Account suspension", "Access revocation"]}]	{T1078,T1530,T1213}	{insider-threat,ueba}	t	0	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
template-ransomware-001	Ransomware Incident	Template for responding to ransomware attacks	ransomware	critical	open	sla-critical-default	[{"order": 1, "title": "Activate Incident Response Team", "priority": "critical", "description": "Assemble full IR team"}, {"order": 2, "title": "Isolate Affected Systems", "priority": "critical", "description": "Prevent ransomware spread"}, {"order": 3, "title": "Identify Ransomware Variant", "priority": "high", "description": "Determine ransomware family"}, {"order": 4, "title": "Assess Encryption Scope", "priority": "high", "description": "Identify all encrypted systems/files"}, {"order": 5, "title": "Check Backups", "priority": "critical", "description": "Verify backup integrity and coverage"}, {"order": 6, "title": "Collect Ransom Note", "priority": "medium", "description": "Preserve ransom demands and payment info"}, {"order": 7, "title": "Notify Stakeholders", "priority": "high", "description": "Alert executive team, legal, PR"}, {"order": 8, "title": "Containment", "priority": "critical", "description": "Stop the spread and preserve evidence"}, {"order": 9, "title": "Recovery Planning", "priority": "high", "description": "Develop restoration strategy"}, {"order": 10, "title": "System Restoration", "priority": "high", "description": "Restore from backups or rebuild"}]	[{"name": "Initial Response", "step": 1, "actions": ["Network segmentation", "Disable RDP/SMB"]}, {"name": "Assessment", "step": 2, "actions": ["Identify patient zero", "Map encryption scope"]}, {"name": "Containment", "step": 3, "actions": ["Isolate systems", "Kill processes"]}, {"name": "Eradication", "step": 4, "actions": ["Remove ransomware", "Patch vulnerabilities"]}, {"name": "Recovery", "step": 5, "actions": ["Restore from backup", "Verify integrity"]}]	{T1486,T1490,T1489,T1562}	{ransomware,critical,business-continuity}	t	0	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
template-account-compromise-001	Account Compromise	Template for investigating compromised user accounts	account_compromise	high	open	sla-high-default	[{"order": 1, "title": "Verify Compromise", "priority": "high", "description": "Confirm account compromise indicators"}, {"order": 2, "title": "Disable Account", "priority": "critical", "description": "Temporarily disable compromised account"}, {"order": 3, "title": "Review Account Activity", "priority": "high", "description": "Analyze login history and actions"}, {"order": 4, "title": "Identify Attack Vector", "priority": "high", "description": "Determine how account was compromised"}, {"order": 5, "title": "Check for Lateral Movement", "priority": "high", "description": "Hunt for additional compromised accounts"}, {"order": 6, "title": "Reset Credentials", "priority": "high", "description": "Force password reset and revoke tokens"}, {"order": 7, "title": "Enable MFA", "priority": "medium", "description": "Ensure MFA is enabled for account"}, {"order": 8, "title": "User Notification", "priority": "medium", "description": "Contact account owner"}]	[{"name": "Detection", "step": 1, "actions": ["Impossible travel", "Anomalous access"]}, {"name": "Containment", "step": 2, "actions": ["Disable account", "Revoke sessions"]}, {"name": "Investigation", "step": 3, "actions": ["Review logs", "Check for data access"]}, {"name": "Recovery", "step": 4, "actions": ["Reset password", "Enable MFA", "Monitor"]}]	{T1078,T1110,T1552}	{account-compromise,credential-theft}	t	0	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
template-ddos-001	DDoS Attack Response	Template for responding to distributed denial of service attacks	ddos	critical	open	sla-critical-default	[{"order": 1, "title": "Confirm DDoS Attack", "priority": "critical", "description": "Verify attack type and scale"}, {"order": 2, "title": "Activate DDoS Mitigation", "priority": "critical", "description": "Enable DDoS protection services"}, {"order": 3, "title": "Notify ISP/CDN", "priority": "high", "description": "Contact service providers for assistance"}, {"order": 4, "title": "Analyze Traffic Patterns", "priority": "high", "description": "Identify attack vectors and sources"}, {"order": 5, "title": "Implement Filtering Rules", "priority": "high", "description": "Block malicious traffic"}, {"order": 6, "title": "Monitor Service Availability", "priority": "high", "description": "Track mitigation effectiveness"}, {"order": 7, "title": "Communicate with Stakeholders", "priority": "medium", "description": "Update business on status"}, {"order": 8, "title": "Post-Attack Analysis", "priority": "low", "description": "Review and improve defenses"}]	[{"name": "Detection", "step": 1, "actions": ["Monitor traffic spikes", "Service health checks"]}, {"name": "Mitigation", "step": 2, "actions": ["Enable rate limiting", "Activate DDoS protection"]}, {"name": "Traffic Analysis", "step": 3, "actions": ["Identify attack type", "Block sources"]}, {"name": "Recovery", "step": 4, "actions": ["Restore services", "Review capacity"]}]	{T1498,T1499}	{ddos,availability,network-attack}	t	0	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
template-webapp-attack-001	Web Application Attack	Template for investigating web application attacks (SQL injection, XSS, etc.)	web_attack	high	open	sla-high-default	[{"order": 1, "title": "Identify Attack Type", "priority": "high", "description": "Determine attack vector (SQLi, XSS, etc.)"}, {"order": 2, "title": "Assess Impact", "priority": "critical", "description": "Check if attack was successful"}, {"order": 3, "title": "Block Attack Source", "priority": "high", "description": "Block malicious IP addresses"}, {"order": 4, "title": "Review WAF Logs", "priority": "high", "description": "Analyze web application firewall logs"}, {"order": 5, "title": "Check for Data Breach", "priority": "critical", "description": "Verify if data was accessed/exfiltrated"}, {"order": 6, "title": "Patch Vulnerability", "priority": "high", "description": "Fix exploited vulnerability"}, {"order": 7, "title": "Update WAF Rules", "priority": "medium", "description": "Add rules to prevent similar attacks"}, {"order": 8, "title": "Vulnerability Scan", "priority": "medium", "description": "Scan for additional vulnerabilities"}]	[{"name": "Detection", "step": 1, "actions": ["WAF alerts", "Anomalous requests"]}, {"name": "Analysis", "step": 2, "actions": ["Review attack payload", "Check database logs"]}, {"name": "Containment", "step": 3, "actions": ["Block attacker", "Disable vulnerable endpoint"]}, {"name": "Remediation", "step": 4, "actions": ["Patch code", "Update WAF", "Pentest"]}]	{T1190,T1211,T1505}	{web-attack,application-security}	t	0	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
\.


--
-- Data for Name: case_watchers; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.case_watchers (case_id, user_id, notification_preferences, created_at) FROM stdin;
\.


--
-- Data for Name: cases; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.cases (case_id, title, description, status, priority, assignee, tags, notes, timeline, activities, resolution_steps, mitre_techniques, created_at, updated_at) FROM stdin;
case-upg-0001	VPN brute force	Opened from f-upg-0001.	in_progress	high	upg.analyst	{vpn,bruteforce}	[]	[{"ts": "2026-10-01T10:05:00", "event": "created"}]	[]	[]	{T1110}	2026-10-01 10:05:00	2026-10-01 10:30:00
case-upg-0002	Scanner noise	\N	closed	low	\N	\N	\N	[]	\N	\N	\N	2026-10-02 12:10:00	2026-10-02 12:20:00
\.


--
-- Data for Name: chat_messages; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.chat_messages (id, conversation_id, seq, role, content, thinking, tool_calls, complete, model, input_tokens, output_tokens, cost_usd, created_at) FROM stdin;
1	conv-upg-0001	1	user	Summarise the case.	\N	[]	t	\N	0	0	0.000000	2026-10-01 10:30:00
2	conv-upg-0001	2	assistant	One VPN brute force, source blocked.	\N	[]	t	\N	50	12	0.000400	2026-10-01 10:31:00
\.


--
-- Data for Name: config_audit_log; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.config_audit_log (id, config_type, config_key, action, old_value, new_value, changed_by, change_reason, "timestamp") FROM stdin;
\.


--
-- Data for Name: conversations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.conversations (id, user_id, title, case_id, page_context, agent_id, model, archived, message_count, created_at, updated_at, last_message_at) FROM stdin;
conv-upg-0001	user-upg-analyst	About case-upg-0001	case-upg-0001	\N	\N	\N	f	2	2026-10-01 10:30:00	2026-10-01 10:31:00	2026-10-01 10:31:00
\.


--
-- Data for Name: custom_agents; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.custom_agents (id, name, description, icon, color, specialization, role, extra_principles, methodology, system_prompt_override, recommended_tools, max_tokens, enable_thinking, model, forked_from, created_by, created_at, updated_at, component_category, fallback_model) FROM stdin;
agent-upg-vpn	VPN triage	Triage VPN alerts	\N	\N	\N	triage			\N	["lookup_ip"]	4096	f	\N	\N	upg.admin	2026-09-20 09:00:00	2026-09-20 09:00:00	investigation	\N
\.


--
-- Data for Name: custom_workflows; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.custom_workflows (workflow_id, name, description, use_case, trigger_examples, phases, is_active, created_by, version, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: episodic_distil_failures; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.episodic_distil_failures (investigation_kind, failure_key, origin_seq, reason, attempts, last_error, first_failed_at, last_failed_at, next_attempt_at, distil_version) FROM stdin;
\.


--
-- Data for Name: episodic_distil_markers; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.episodic_distil_markers (investigation_kind, investigation_id, origin_run_id, origin_seq, origin_run_ids, distil_version, sightings_written, verdicts_written, gaps_written, concluded_at, distilled_at) FROM stdin;
\.


--
-- Data for Name: episodic_gaps; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.episodic_gaps (id, investigation_kind, investigation_id, hypothesis_id, statement, disposition, reason, subject_entities, concluded_at) FROM stdin;
\.


--
-- Data for Name: episodic_read_log; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.episodic_read_log (id, ts, caller_kind, caller_id, keys, as_of, row_counts, dropped, ranking) FROM stdin;
\.


--
-- Data for Name: episodic_sightings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.episodic_sightings (id, entity_key, investigation_kind, investigation_id, source_system, hit_count, attacker_influenceable, first_seen, last_seen, concluded_at) FROM stdin;
\.


--
-- Data for Name: episodic_verdict_sources; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.episodic_verdict_sources (id, verdict_id, source_system, stance, source_tier) FROM stdin;
\.


--
-- Data for Name: episodic_verdicts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.episodic_verdicts (id, investigation_kind, investigation_id, hypothesis_id, statement, outcome, rationale, subject_entities, attacker_influenceable_only, trust, first_seen, last_seen, window_source, concluded_at, techniques) FROM stdin;
\.


--
-- Data for Name: federation_sources; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.federation_sources (source_id, enabled, interval_seconds, max_items, min_severity, cursor, last_poll_at, last_success_at, last_error, consecutive_errors, dropped_total, created_at, updated_at) FROM stdin;
splunk	t	300	100	\N	{"last_time": "2026-10-02T12:00:00Z"}	\N	\N	\N	0	0	2026-10-13 12:41:22.898412+00	2026-10-13 12:41:22.898412+00
\.


--
-- Data for Name: finding_mitre_predictions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.finding_mitre_predictions (finding_id, technique_id, confidence) FROM stdin;
\.


--
-- Data for Name: findings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.findings (finding_id, anomaly_score, title, description, entity_context, evidence_links, "timestamp", data_source, external_id, cluster_id, severity, status, noise_marked_at, noise_marked_by, ai_enrichment, created_at, updated_at) FROM stdin;
f-upg-0001	0.91	Brute force against VPN gateway	Repeated failed logins from one source.	{"user": "upg.analyst", "src_ip": "192.0.2.10"}	[]	2026-10-01 10:00:00	splunk	ext-1	\N	high	new	\N	\N	\N	2026-10-01 10:00:05	2026-10-01 10:00:05
f-upg-0002	0.42	Unusual PowerShell child process	\N	{"host": "ws-upg-01.example.com"}	[]	2026-10-01 11:00:00	crowdstrike	ext-2	\N	medium	in_review	\N	\N	\N	2026-10-01 11:00:05	2026-10-01 11:00:05
f-upg-0003	\N	Imported historical alert	\N	{}	[]	\N	splunk	ext-3	\N	\N	new	\N	\N	\N	2026-09-15 09:00:00	2026-09-15 09:00:00
f-upg-0004	0.1	Benign scanner	Internal vulnerability scanner.	{"src_ip": "198.51.100.7"}	[]	2026-10-02 12:00:00	splunk	ext-4	\N	low	closed	\N	\N	\N	2026-10-02 12:00:05	2026-10-02 12:00:05
\.


--
-- Data for Name: intake_triggers; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.intake_triggers (id, kind, state, reason, finding_id, priority, payload, investigation_id, case_id, merged_into, created_at, decided_at) FROM stdin;
\.


--
-- Data for Name: integration_configs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.integration_configs (integration_id, enabled, config, integration_name, integration_type, description, last_test_at, last_test_success, last_error, updated_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: investigation_logs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.investigation_logs (id, investigation_id, "timestamp", event_type, details, tokens_used) FROM stdin;
\.


--
-- Data for Name: investigations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.investigations (investigation_id, case_id, workflow_id, trigger_type, trigger_ids, status, workdir, current_step, total_steps, iteration_count, max_iterations, input_tokens, output_tokens, cost_usd, max_cost_usd, priority, created_at, started_at, completed_at, last_activity_at, max_runtime_seconds, summary, proposed_actions, master_review_notes, error_count, last_error, current_activity) FROM stdin;
\.


--
-- Data for Name: ip_exclusions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.ip_exclusions (exclusion_id, ip, reason, origin, origin_ref, created_by, created_at, removed_at, removed_by, removal_reason) FROM stdin;
excl-upg-0001	198.51.100.7	Internal scanner	ad_hoc	\N	upg.admin	2026-10-02 12:15:00	\N	\N	\N
\.


--
-- Data for Name: llm_interaction_logs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.llm_interaction_logs (id, interaction_id, session_id, agent_id, investigation_id, created_at, model, request_messages, system_prompt, thinking_enabled, thinking_budget, thinking_content, response_content, tool_calls, tool_results, stop_reason, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, cost_usd, input_cost_per_token, output_cost_per_token, cache_read_cost_per_token, cache_write_cost_per_token, rates_fetched_at, duration_ms, error, virtual_key_id) FROM stdin;
1	llm-upg-0001	sess-upg	agent-upg-vpn	\N	2026-10-01 10:06:10	claude-sonnet	[{"role": "user", "content": "triage f-upg-0001"}]	\N	f	\N	\N	\N	[]	[]	\N	1200	300	0	0	0.008100	\N	\N	\N	\N	\N	2100	\N	\N
\.


--
-- Data for Name: llm_provider_configs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.llm_provider_configs (provider_id, provider_type, name, base_url, api_key_ref, default_model, is_active, is_default, config, last_test_at, last_test_success, last_error, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: mcp_credentials; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.mcp_credentials (credential_id, user_id, token_hash, label, created_at, last_used_at, expires_at, revoked_at) FROM stdin;
\.


--
-- Data for Name: roles; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.roles (role_id, name, description, permissions, is_system_role, created_at, updated_at) FROM stdin;
role-viewer	Viewer	Read-only access to findings and cases	{"cases.read": true, "users.read": false, "ai_chat.use": false, "findings.read": true, "settings.read": false, "integrations.read": false, "ai_decisions.approve": false}	t	2026-10-13 12:40:30.336628	2026-10-13 12:40:30.336628
role-analyst	Analyst	Full access to findings and cases, limited integrations	{"cases.read": true, "loglm.view": true, "users.read": false, "ai_chat.use": true, "cases.write": true, "cases.assign": false, "cases.delete": false, "findings.read": true, "settings.read": true, "findings.write": true, "settings.write": false, "findings.delete": false, "integrations.read": true, "integrations.write": false, "ai_decisions.approve": false}	t	2026-10-13 12:40:30.336628	2026-10-13 12:40:37.924299
role-senior-analyst	Senior Analyst	Full analyst access plus approval rights	{"cases.read": true, "loglm.view": true, "users.read": true, "ai_chat.use": true, "cases.write": true, "cases.assign": true, "cases.delete": false, "findings.read": true, "settings.read": true, "findings.write": true, "settings.write": false, "findings.delete": true, "integrations.read": true, "integrations.write": true, "ai_decisions.approve": true}	t	2026-10-13 12:40:30.336628	2026-10-13 12:40:37.924299
role-manager	Manager	User management and all integrations	{"cases.read": true, "loglm.view": true, "users.read": true, "ai_chat.use": true, "cases.write": true, "users.write": true, "cases.assign": true, "cases.delete": true, "users.delete": false, "findings.read": true, "settings.read": true, "findings.write": true, "settings.write": true, "findings.delete": true, "integrations.read": true, "integrations.write": true, "ai_decisions.approve": true}	t	2026-10-13 12:40:30.336628	2026-10-13 12:40:37.924299
role-admin	Admin	Full system access	{"cases.read": true, "loglm.view": true, "users.read": true, "ai_chat.use": true, "cases.write": true, "users.write": true, "cases.assign": true, "cases.delete": true, "users.delete": true, "findings.read": true, "settings.read": true, "findings.write": true, "settings.write": true, "findings.delete": true, "integrations.read": true, "integrations.write": true, "ai_decisions.approve": true}	t	2026-10-13 12:40:30.336628	2026-10-13 12:40:37.924299
\.


--
-- Data for Name: shared_iocs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.shared_iocs (id, investigation_id, ioc_type, value, created_at) FROM stdin;
\.


--
-- Data for Name: sketch_mappings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.sketch_mappings (id, case_id, finding_id, sketch_id, sketch_name, sketch_url, created_at) FROM stdin;
\.


--
-- Data for Name: sla_policies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.sla_policies (policy_id, name, description, priority_level, response_time_hours, resolution_time_hours, business_hours_only, escalation_rules, notification_thresholds, is_active, is_default, created_at, updated_at) FROM stdin;
sla-critical-default	Critical Priority SLA	Standard SLA for critical priority cases requiring immediate attention	critical	1	4	f	\N	{75,90,100}	t	t	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
sla-high-default	High Priority SLA	Standard SLA for high priority cases	high	2	8	f	\N	{75,90,100}	t	t	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
sla-medium-default	Medium Priority SLA	Standard SLA for medium priority cases	medium	4	24	t	\N	{75,90,100}	t	t	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
sla-low-default	Low Priority SLA	Standard SLA for low priority cases	low	8	72	t	\N	{75,90,100}	t	t	2026-10-13 12:41:01.412323	2026-10-13 12:41:01.412323
\.


--
-- Data for Name: system_config; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.system_config (key, value, description, config_type, updated_by, created_at, updated_at) FROM stdin;
general.settings	{"theme": "dark", "enable_keyring": false, "auto_start_sync": false, "show_notifications": true}	General application settings	general	\N	2026-10-13 12:40:28.628421	2026-10-13 12:40:28.628421
approval.force_manual_approval	{"enabled": false}	Force manual approval for all actions regardless of confidence score	approval	\N	2026-10-13 12:40:28.636741	2026-10-13 12:40:28.636741
theme.current	{"theme": "dark"}	Current UI theme	theme	\N	2026-10-13 12:40:28.644422	2026-10-13 12:40:28.644422
federation.settings	{"enabled": false}	Federated monitoring global on/off (per-source toggles live in federation_sources)	federation	\N	2026-10-13 12:40:37.024431	2026-10-13 12:40:37.024431
bifrost.virtual_keys	{"default_vk": "", "budget_limit_usd": 0, "enforcement_mode": "warning"}	Bifrost virtual-key configuration and budget settings (#186)	ai	\N	2026-10-13 12:40:37.513779	2026-10-13 12:40:37.513779
schema_version	{"version": "0.7.1"}	Vigil version this schema was last provisioned at	system	\N	2026-10-13 12:41:01.492807	2026-10-13 12:41:01.492807
upgrade_fixture.marker	{"from": "0.7.1"}	Upgrade fixture marker row	system	\N	2026-10-13 12:41:22.898412	2026-10-13 12:41:22.898412
\.


--
-- Data for Name: threat_indicators; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.threat_indicators (id, indicator_type, indicator_value, source, collection_id, confidence, threat_level, labels, valid_from, valid_until, raw_stix, first_seen, last_seen) FROM stdin;
1	ipv4-addr	192.0.2.10	taxii-upgrade-fixture	\N	80.00	high	{bruteforce}	\N	\N	\N	2026-10-01 10:00:00	2026-10-01 10:00:00
\.


--
-- Data for Name: user_preferences; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_preferences (user_id, preferences, display_name, email, created_at, updated_at, last_login) FROM stdin;
default	{"theme": "dark", "auto_start_sync": false, "show_notifications": true}	Default User	\N	2026-10-13 12:40:28.656426	2026-10-13 12:40:28.656426	\N
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.users (user_id, username, email, password_hash, full_name, role_id, is_active, is_verified, mfa_enabled, mfa_secret, mfa_recovery_codes, last_login, login_count, failed_login_count, locked_until, password_history, password_changed_at, created_at, updated_at) FROM stdin;
user-upg-analyst	upg.analyst	upg.analyst@example.com	not-a-hash-upgrade-fixture	Upgrade Analyst	role-analyst	t	t	f	\N	[]	\N	7	0	\N	[]	\N	2026-09-01 08:00:00	2026-09-01 08:00:00
user-upg-admin	upg.admin	upg.admin@example.com	not-a-hash-upgrade-fixture	Upgrade Admin	role-admin	t	t	f	\N	[]	\N	3	0	\N	[]	\N	2026-09-01 08:00:00	2026-09-01 08:00:00
\.


--
-- Data for Name: workflow_run_phases; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.workflow_run_phases (run_id, phase_id, phase_order, agent_id, status, started_at, finished_at, duration_ms, input_context, output, approval_state, cost_usd, error) FROM stdin;
\.


--
-- Data for Name: workflow_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.workflow_runs (run_id, workflow_id, workflow_version, workflow_source, workflow_name, status, triggered_by, trigger_context, started_at, finished_at, duration_ms, total_cost_usd, result_summary, error, deleted_at, outcome, reason) FROM stdin;
wfr-upg-0001	incident-response	1	file	Incident response	completed	upg.analyst	{"case_id": "case-upg-0001"}	2026-10-01 10:08:00	2026-10-01 10:09:00	60000	0.0123	Contained	\N	\N	completed	\N
\.


--
-- Name: agent_directives_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.agent_directives_id_seq', 1, false);


--
-- Name: ai_decision_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.ai_decision_logs_id_seq', 1, false);


--
-- Name: case_attachments_attachment_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.case_attachments_attachment_id_seq', 1, false);


--
-- Name: case_audit_logs_audit_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.case_audit_logs_audit_id_seq', 1, false);


--
-- Name: case_comments_comment_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.case_comments_comment_id_seq', 1, true);


--
-- Name: case_escalations_escalation_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.case_escalations_escalation_id_seq', 1, false);


--
-- Name: case_evidence_evidence_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.case_evidence_evidence_id_seq', 1, false);


--
-- Name: case_iocs_ioc_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.case_iocs_ioc_id_seq', 1, true);


--
-- Name: case_notifications_notification_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.case_notifications_notification_id_seq', 1, false);


--
-- Name: case_relationships_relationship_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.case_relationships_relationship_id_seq', 1, false);


--
-- Name: case_slas_sla_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.case_slas_sla_id_seq', 1, false);


--
-- Name: case_tasks_task_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.case_tasks_task_id_seq', 1, false);


--
-- Name: chat_messages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.chat_messages_id_seq', 2, true);


--
-- Name: config_audit_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.config_audit_log_id_seq', 1, false);


--
-- Name: episodic_gaps_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.episodic_gaps_id_seq', 1, false);


--
-- Name: episodic_read_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.episodic_read_log_id_seq', 1, false);


--
-- Name: episodic_sightings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.episodic_sightings_id_seq', 1, false);


--
-- Name: episodic_verdict_sources_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.episodic_verdict_sources_id_seq', 1, false);


--
-- Name: episodic_verdicts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.episodic_verdicts_id_seq', 1, false);


--
-- Name: intake_triggers_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.intake_triggers_id_seq', 1, false);


--
-- Name: investigation_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.investigation_logs_id_seq', 1, false);


--
-- Name: llm_interaction_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.llm_interaction_logs_id_seq', 1, true);


--
-- Name: shared_iocs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.shared_iocs_id_seq', 1, false);


--
-- Name: sketch_mappings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.sketch_mappings_id_seq', 1, false);


--
-- Name: threat_indicators_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.threat_indicators_id_seq', 1, true);


--
-- Name: agent_directives agent_directives_directive_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_directives
    ADD CONSTRAINT agent_directives_directive_id_key UNIQUE (directive_id);


--
-- Name: agent_directives agent_directives_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_directives
    ADD CONSTRAINT agent_directives_pkey PRIMARY KEY (id);


--
-- Name: agent_events agent_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_events
    ADD CONSTRAINT agent_events_pkey PRIMARY KEY (run_id, seq);


--
-- Name: agent_run_leases agent_run_leases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_run_leases
    ADD CONSTRAINT agent_run_leases_pkey PRIMARY KEY (run_id);


--
-- Name: ai_decision_logs ai_decision_logs_decision_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_decision_logs
    ADD CONSTRAINT ai_decision_logs_decision_id_key UNIQUE (decision_id);


--
-- Name: ai_decision_logs ai_decision_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_decision_logs
    ADD CONSTRAINT ai_decision_logs_pkey PRIMARY KEY (id);


--
-- Name: ai_model_configs ai_model_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_model_configs
    ADD CONSTRAINT ai_model_configs_pkey PRIMARY KEY (component);


--
-- Name: approval_actions approval_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_actions
    ADD CONSTRAINT approval_actions_pkey PRIMARY KEY (action_id);


--
-- Name: case_attachments case_attachments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_attachments
    ADD CONSTRAINT case_attachments_pkey PRIMARY KEY (attachment_id);


--
-- Name: case_audit_logs case_audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_audit_logs
    ADD CONSTRAINT case_audit_logs_pkey PRIMARY KEY (audit_id);


--
-- Name: case_closure_info case_closure_info_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_closure_info
    ADD CONSTRAINT case_closure_info_pkey PRIMARY KEY (case_id);


--
-- Name: case_comments case_comments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_comments
    ADD CONSTRAINT case_comments_pkey PRIMARY KEY (comment_id);


--
-- Name: case_escalations case_escalations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_escalations
    ADD CONSTRAINT case_escalations_pkey PRIMARY KEY (escalation_id);


--
-- Name: case_evidence case_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_evidence
    ADD CONSTRAINT case_evidence_pkey PRIMARY KEY (evidence_id);


--
-- Name: case_findings case_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_findings
    ADD CONSTRAINT case_findings_pkey PRIMARY KEY (case_id, finding_id);


--
-- Name: case_iocs case_iocs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_iocs
    ADD CONSTRAINT case_iocs_pkey PRIMARY KEY (ioc_id);


--
-- Name: case_metrics case_metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_metrics
    ADD CONSTRAINT case_metrics_pkey PRIMARY KEY (case_id);


--
-- Name: case_notifications case_notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_notifications
    ADD CONSTRAINT case_notifications_pkey PRIMARY KEY (notification_id);


--
-- Name: case_relationships case_relationships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_relationships
    ADD CONSTRAINT case_relationships_pkey PRIMARY KEY (relationship_id);


--
-- Name: case_slas case_slas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_slas
    ADD CONSTRAINT case_slas_pkey PRIMARY KEY (sla_id);


--
-- Name: case_tasks case_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_tasks
    ADD CONSTRAINT case_tasks_pkey PRIMARY KEY (task_id);


--
-- Name: case_templates case_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_templates
    ADD CONSTRAINT case_templates_pkey PRIMARY KEY (template_id);


--
-- Name: case_watchers case_watchers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_watchers
    ADD CONSTRAINT case_watchers_pkey PRIMARY KEY (case_id, user_id);


--
-- Name: cases cases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cases
    ADD CONSTRAINT cases_pkey PRIMARY KEY (case_id);


--
-- Name: chat_messages chat_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT chat_messages_pkey PRIMARY KEY (id);


--
-- Name: config_audit_log config_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.config_audit_log
    ADD CONSTRAINT config_audit_log_pkey PRIMARY KEY (id);


--
-- Name: conversations conversations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversations
    ADD CONSTRAINT conversations_pkey PRIMARY KEY (id);


--
-- Name: custom_agents custom_agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_agents
    ADD CONSTRAINT custom_agents_pkey PRIMARY KEY (id);


--
-- Name: custom_workflows custom_workflows_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_workflows
    ADD CONSTRAINT custom_workflows_pkey PRIMARY KEY (workflow_id);


--
-- Name: episodic_distil_failures episodic_distil_failures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_distil_failures
    ADD CONSTRAINT episodic_distil_failures_pkey PRIMARY KEY (investigation_kind, failure_key);


--
-- Name: episodic_distil_markers episodic_distil_markers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_distil_markers
    ADD CONSTRAINT episodic_distil_markers_pkey PRIMARY KEY (investigation_kind, investigation_id);


--
-- Name: episodic_gaps episodic_gaps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_gaps
    ADD CONSTRAINT episodic_gaps_pkey PRIMARY KEY (id);


--
-- Name: episodic_gaps episodic_gaps_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_gaps
    ADD CONSTRAINT episodic_gaps_unique UNIQUE (investigation_kind, investigation_id, hypothesis_id);


--
-- Name: episodic_read_log episodic_read_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_read_log
    ADD CONSTRAINT episodic_read_log_pkey PRIMARY KEY (id);


--
-- Name: episodic_sightings episodic_sightings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_sightings
    ADD CONSTRAINT episodic_sightings_pkey PRIMARY KEY (id);


--
-- Name: episodic_sightings episodic_sightings_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_sightings
    ADD CONSTRAINT episodic_sightings_unique UNIQUE (entity_key, investigation_kind, investigation_id, source_system);


--
-- Name: episodic_verdict_sources episodic_verdict_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_verdict_sources
    ADD CONSTRAINT episodic_verdict_sources_pkey PRIMARY KEY (id);


--
-- Name: episodic_verdict_sources episodic_verdict_sources_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_verdict_sources
    ADD CONSTRAINT episodic_verdict_sources_unique UNIQUE (verdict_id, source_system);


--
-- Name: episodic_verdicts episodic_verdicts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_verdicts
    ADD CONSTRAINT episodic_verdicts_pkey PRIMARY KEY (id);


--
-- Name: episodic_verdicts episodic_verdicts_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_verdicts
    ADD CONSTRAINT episodic_verdicts_unique UNIQUE (investigation_kind, investigation_id, hypothesis_id);


--
-- Name: federation_sources federation_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_sources
    ADD CONSTRAINT federation_sources_pkey PRIMARY KEY (source_id);


--
-- Name: finding_mitre_predictions finding_mitre_predictions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_mitre_predictions
    ADD CONSTRAINT finding_mitre_predictions_pkey PRIMARY KEY (finding_id, technique_id);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (finding_id);


--
-- Name: intake_triggers intake_triggers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_triggers
    ADD CONSTRAINT intake_triggers_pkey PRIMARY KEY (id);


--
-- Name: integration_configs integration_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_configs
    ADD CONSTRAINT integration_configs_pkey PRIMARY KEY (integration_id);


--
-- Name: investigation_logs investigation_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_logs
    ADD CONSTRAINT investigation_logs_pkey PRIMARY KEY (id);


--
-- Name: investigations investigations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigations
    ADD CONSTRAINT investigations_pkey PRIMARY KEY (investigation_id);


--
-- Name: ip_exclusions ip_exclusions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_exclusions
    ADD CONSTRAINT ip_exclusions_pkey PRIMARY KEY (exclusion_id);


--
-- Name: llm_interaction_logs llm_interaction_logs_interaction_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_interaction_logs
    ADD CONSTRAINT llm_interaction_logs_interaction_id_key UNIQUE (interaction_id);


--
-- Name: llm_interaction_logs llm_interaction_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_interaction_logs
    ADD CONSTRAINT llm_interaction_logs_pkey PRIMARY KEY (id);


--
-- Name: llm_provider_configs llm_provider_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_provider_configs
    ADD CONSTRAINT llm_provider_configs_pkey PRIMARY KEY (provider_id);


--
-- Name: mcp_credentials mcp_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_credentials
    ADD CONSTRAINT mcp_credentials_pkey PRIMARY KEY (credential_id);


--
-- Name: mcp_credentials mcp_credentials_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_credentials
    ADD CONSTRAINT mcp_credentials_token_hash_key UNIQUE (token_hash);


--
-- Name: roles roles_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_name_key UNIQUE (name);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (role_id);


--
-- Name: shared_iocs shared_iocs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_iocs
    ADD CONSTRAINT shared_iocs_pkey PRIMARY KEY (id);


--
-- Name: sketch_mappings sketch_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sketch_mappings
    ADD CONSTRAINT sketch_mappings_pkey PRIMARY KEY (id);


--
-- Name: sla_policies sla_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sla_policies
    ADD CONSTRAINT sla_policies_pkey PRIMARY KEY (policy_id);


--
-- Name: system_config system_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_config
    ADD CONSTRAINT system_config_pkey PRIMARY KEY (key);


--
-- Name: threat_indicators threat_indicators_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_indicators
    ADD CONSTRAINT threat_indicators_pkey PRIMARY KEY (id);


--
-- Name: threat_indicators threat_indicators_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_indicators
    ADD CONSTRAINT threat_indicators_unique UNIQUE (source, indicator_type, indicator_value);


--
-- Name: chat_messages uq_chat_messages_conv_seq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT uq_chat_messages_conv_seq UNIQUE (conversation_id, seq);


--
-- Name: user_preferences user_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_preferences
    ADD CONSTRAINT user_preferences_pkey PRIMARY KEY (user_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: workflow_run_phases workflow_run_phases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_run_phases
    ADD CONSTRAINT workflow_run_phases_pkey PRIMARY KEY (run_id, phase_id);


--
-- Name: workflow_runs workflow_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_pkey PRIMARY KEY (run_id);


--
-- Name: idx_agent_directives_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_directives_run ON public.agent_directives USING btree (run_id, id);


--
-- Name: idx_agent_events_terminal; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_events_terminal ON public.agent_events USING btree (run_id) WHERE (kind = 'terminal'::text);


--
-- Name: idx_agent_run_leases_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_run_leases_due ON public.agent_run_leases USING btree (claim_until);


--
-- Name: idx_ai_decision_actual_outcome; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_decision_actual_outcome ON public.ai_decision_logs USING btree (actual_outcome);


--
-- Name: idx_ai_decision_agent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_decision_agent_id ON public.ai_decision_logs USING btree (agent_id);


--
-- Name: idx_ai_decision_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_decision_case_id ON public.ai_decision_logs USING btree (case_id);


--
-- Name: idx_ai_decision_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_decision_finding_id ON public.ai_decision_logs USING btree (finding_id);


--
-- Name: idx_ai_decision_human_decision; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_decision_human_decision ON public.ai_decision_logs USING btree (human_decision);


--
-- Name: idx_ai_decision_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_decision_timestamp ON public.ai_decision_logs USING btree ("timestamp");


--
-- Name: idx_ai_model_configs_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_model_configs_provider ON public.ai_model_configs USING btree (provider_id);


--
-- Name: idx_approval_actions_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_actions_pending ON public.approval_actions USING btree (created_at DESC) WHERE (((status)::text = 'pending'::text) AND (requires_approval = true));


--
-- Name: idx_approval_actions_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_actions_status_created ON public.approval_actions USING btree (status, created_at DESC);


--
-- Name: idx_approval_actions_workflow_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_actions_workflow_run ON public.approval_actions USING btree (workflow_run_id) WHERE (workflow_run_id IS NOT NULL);


--
-- Name: idx_audit_changed_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_changed_by ON public.config_audit_log USING btree (changed_by);


--
-- Name: idx_audit_config_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_config_key ON public.config_audit_log USING btree (config_key);


--
-- Name: idx_audit_config_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_config_type ON public.config_audit_log USING btree (config_type);


--
-- Name: idx_audit_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_timestamp ON public.config_audit_log USING btree ("timestamp");


--
-- Name: idx_case_assignee; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_assignee ON public.cases USING btree (assignee);


--
-- Name: idx_case_attachment_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_attachment_case_id ON public.case_attachments USING btree (case_id);


--
-- Name: idx_case_attachment_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_attachment_created_at ON public.case_attachments USING btree (created_at);


--
-- Name: idx_case_attachment_uploaded_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_attachment_uploaded_by ON public.case_attachments USING btree (uploaded_by);


--
-- Name: idx_case_audit_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_audit_action ON public.case_audit_logs USING btree (action);


--
-- Name: idx_case_audit_changed_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_audit_changed_by ON public.case_audit_logs USING btree (changed_by);


--
-- Name: idx_case_audit_entity_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_audit_entity_id ON public.case_audit_logs USING btree (entity_id);


--
-- Name: idx_case_audit_entity_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_audit_entity_type ON public.case_audit_logs USING btree (entity_type);


--
-- Name: idx_case_audit_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_audit_timestamp ON public.case_audit_logs USING btree ("timestamp");


--
-- Name: idx_case_comment_author; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_comment_author ON public.case_comments USING btree (author);


--
-- Name: idx_case_comment_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_comment_case_id ON public.case_comments USING btree (case_id);


--
-- Name: idx_case_comment_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_comment_created_at ON public.case_comments USING btree (created_at);


--
-- Name: idx_case_comment_parent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_comment_parent_id ON public.case_comments USING btree (parent_comment_id);


--
-- Name: idx_case_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_created_at ON public.cases USING btree (created_at);


--
-- Name: idx_case_escalation_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_escalation_case_id ON public.case_escalations USING btree (case_id);


--
-- Name: idx_case_escalation_escalated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_escalation_escalated_at ON public.case_escalations USING btree (escalated_at);


--
-- Name: idx_case_escalation_escalated_to; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_escalation_escalated_to ON public.case_escalations USING btree (escalated_to);


--
-- Name: idx_case_escalation_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_escalation_status ON public.case_escalations USING btree (status);


--
-- Name: idx_case_evidence_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_evidence_case_id ON public.case_evidence USING btree (case_id);


--
-- Name: idx_case_evidence_collected_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_evidence_collected_at ON public.case_evidence USING btree (collected_at);


--
-- Name: idx_case_evidence_collected_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_evidence_collected_by ON public.case_evidence USING btree (collected_by);


--
-- Name: idx_case_evidence_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_evidence_type ON public.case_evidence USING btree (evidence_type);


--
-- Name: idx_case_findings_finding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_findings_finding ON public.case_findings USING btree (finding_id, case_id);


--
-- Name: idx_case_ioc_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_ioc_case_id ON public.case_iocs USING btree (case_id);


--
-- Name: idx_case_ioc_is_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_ioc_is_active ON public.case_iocs USING btree (is_active);


--
-- Name: idx_case_ioc_threat_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_ioc_threat_level ON public.case_iocs USING btree (threat_level);


--
-- Name: idx_case_ioc_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_ioc_type ON public.case_iocs USING btree (ioc_type);


--
-- Name: idx_case_ioc_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_ioc_value ON public.case_iocs USING btree (value);


--
-- Name: idx_case_notification_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_notification_case_id ON public.case_notifications USING btree (case_id);


--
-- Name: idx_case_notification_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_notification_created_at ON public.case_notifications USING btree (created_at);


--
-- Name: idx_case_notification_is_read; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_notification_is_read ON public.case_notifications USING btree (is_read);


--
-- Name: idx_case_notification_is_sent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_notification_is_sent ON public.case_notifications USING btree (is_sent);


--
-- Name: idx_case_notification_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_notification_type ON public.case_notifications USING btree (notification_type);


--
-- Name: idx_case_notification_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_notification_user_id ON public.case_notifications USING btree (user_id);


--
-- Name: idx_case_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_priority ON public.cases USING btree (priority);


--
-- Name: idx_case_relationship_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_relationship_case_id ON public.case_relationships USING btree (case_id);


--
-- Name: idx_case_relationship_related_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_relationship_related_case_id ON public.case_relationships USING btree (related_case_id);


--
-- Name: idx_case_relationship_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_relationship_type ON public.case_relationships USING btree (relationship_type);


--
-- Name: idx_case_sla_breached; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_sla_breached ON public.case_slas USING btree (breached);


--
-- Name: idx_case_sla_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_sla_case_id ON public.case_slas USING btree (case_id);


--
-- Name: idx_case_sla_policy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_sla_policy_id ON public.case_slas USING btree (sla_policy_id);


--
-- Name: idx_case_sla_resolution_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_sla_resolution_due ON public.case_slas USING btree (resolution_due);


--
-- Name: idx_case_sla_response_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_sla_response_due ON public.case_slas USING btree (response_due);


--
-- Name: idx_case_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_status ON public.cases USING btree (status);


--
-- Name: idx_case_task_assignee; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_task_assignee ON public.case_tasks USING btree (assignee);


--
-- Name: idx_case_task_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_task_case_id ON public.case_tasks USING btree (case_id);


--
-- Name: idx_case_task_due_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_task_due_date ON public.case_tasks USING btree (due_date);


--
-- Name: idx_case_task_parent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_task_parent_id ON public.case_tasks USING btree (parent_task_id);


--
-- Name: idx_case_task_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_task_status ON public.case_tasks USING btree (status);


--
-- Name: idx_case_template_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_template_active ON public.case_templates USING btree (is_active);


--
-- Name: idx_case_template_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_template_type ON public.case_templates USING btree (template_type);


--
-- Name: idx_case_template_usage_count; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_template_usage_count ON public.case_templates USING btree (usage_count);


--
-- Name: idx_case_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_updated_at ON public.cases USING btree (updated_at);


--
-- Name: idx_case_watcher_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_watcher_case_id ON public.case_watchers USING btree (case_id);


--
-- Name: idx_case_watcher_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_watcher_user_id ON public.case_watchers USING btree (user_id);


--
-- Name: idx_chat_messages_conversation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_messages_conversation ON public.chat_messages USING btree (conversation_id);


--
-- Name: idx_conversations_user_archived; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_conversations_user_archived ON public.conversations USING btree (user_id, archived);


--
-- Name: idx_conversations_user_last_msg; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_conversations_user_last_msg ON public.conversations USING btree (user_id, last_message_at);


--
-- Name: idx_custom_agents_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_custom_agents_updated_at ON public.custom_agents USING btree (updated_at DESC);


--
-- Name: idx_custom_workflows_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_custom_workflows_active ON public.custom_workflows USING btree (is_active);


--
-- Name: idx_custom_workflows_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_custom_workflows_created_by ON public.custom_workflows USING btree (created_by);


--
-- Name: idx_custom_workflows_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_custom_workflows_name ON public.custom_workflows USING btree (name);


--
-- Name: idx_episodic_gaps_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_gaps_investigation ON public.episodic_gaps USING btree (investigation_kind, investigation_id);


--
-- Name: idx_episodic_gaps_recall; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_gaps_recall ON public.episodic_gaps USING btree (concluded_at DESC, id);


--
-- Name: idx_episodic_gaps_subjects; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_gaps_subjects ON public.episodic_gaps USING gin (subject_entities);


--
-- Name: idx_episodic_markers_origin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_markers_origin ON public.episodic_distil_markers USING gin (origin_run_ids);


--
-- Name: idx_episodic_read_log_keys; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_read_log_keys ON public.episodic_read_log USING gin (keys);


--
-- Name: idx_episodic_read_log_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_read_log_ts ON public.episodic_read_log USING btree (ts);


--
-- Name: idx_episodic_sightings_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_sightings_investigation ON public.episodic_sightings USING btree (investigation_kind, investigation_id);


--
-- Name: idx_episodic_sightings_recall; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_sightings_recall ON public.episodic_sightings USING btree (entity_key, concluded_at DESC, id);


--
-- Name: idx_episodic_verdicts_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_verdicts_investigation ON public.episodic_verdicts USING btree (investigation_kind, investigation_id);


--
-- Name: idx_episodic_verdicts_recall; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_verdicts_recall ON public.episodic_verdicts USING btree (concluded_at DESC, id);


--
-- Name: idx_episodic_verdicts_subjects; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_verdicts_subjects ON public.episodic_verdicts USING gin (subject_entities);


--
-- Name: idx_episodic_verdicts_techniques; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_episodic_verdicts_techniques ON public.episodic_verdicts USING gin (techniques);


--
-- Name: idx_federation_sources_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_federation_sources_enabled ON public.federation_sources USING btree (enabled);


--
-- Name: idx_finding_anomaly_score; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_anomaly_score ON public.findings USING btree (anomaly_score);


--
-- Name: idx_finding_cluster_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_cluster_id ON public.findings USING btree (cluster_id);


--
-- Name: idx_finding_data_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_data_source ON public.findings USING btree (data_source);


--
-- Name: idx_finding_description; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_description ON public.findings USING gin (description public.gin_trgm_ops);


--
-- Name: idx_finding_mitre_predictions_technique_confidence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_mitre_predictions_technique_confidence ON public.finding_mitre_predictions USING btree (technique_id, confidence DESC);


--
-- Name: idx_finding_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_severity ON public.findings USING btree (severity);


--
-- Name: idx_finding_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_status ON public.findings USING btree (status);


--
-- Name: idx_finding_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_timestamp ON public.findings USING btree ("timestamp");


--
-- Name: idx_intake_triggers_queued_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_triggers_queued_created ON public.intake_triggers USING btree (created_at) WHERE ((state)::text = 'queued'::text);


--
-- Name: idx_integration_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_enabled ON public.integration_configs USING btree (enabled);


--
-- Name: idx_integration_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_type ON public.integration_configs USING btree (integration_type);


--
-- Name: idx_integration_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_updated_at ON public.integration_configs USING btree (updated_at);


--
-- Name: idx_inv_log_event_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_log_event_type ON public.investigation_logs USING btree (event_type);


--
-- Name: idx_inv_log_investigation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_log_investigation_id ON public.investigation_logs USING btree (investigation_id);


--
-- Name: idx_inv_log_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_log_timestamp ON public.investigation_logs USING btree ("timestamp");


--
-- Name: idx_investigation_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_case_id ON public.investigations USING btree (case_id);


--
-- Name: idx_investigation_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_created_at ON public.investigations USING btree (created_at);


--
-- Name: idx_investigation_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_priority ON public.investigations USING btree (priority);


--
-- Name: idx_investigation_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_status ON public.investigations USING btree (status);


--
-- Name: idx_investigation_workflow_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_workflow_id ON public.investigations USING btree (workflow_id);


--
-- Name: idx_ip_exclusions_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ip_exclusions_created_at ON public.ip_exclusions USING btree (created_at DESC);


--
-- Name: idx_llm_interaction_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_interaction_agent ON public.llm_interaction_logs USING btree (agent_id);


--
-- Name: idx_llm_interaction_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_interaction_created ON public.llm_interaction_logs USING btree (created_at);


--
-- Name: idx_llm_interaction_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_interaction_investigation ON public.llm_interaction_logs USING btree (investigation_id);


--
-- Name: idx_llm_interaction_session; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_interaction_session ON public.llm_interaction_logs USING btree (session_id);


--
-- Name: idx_llm_interaction_vk; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_interaction_vk ON public.llm_interaction_logs USING btree (virtual_key_id, created_at);


--
-- Name: idx_llm_provider_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_provider_active ON public.llm_provider_configs USING btree (is_active);


--
-- Name: idx_llm_provider_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_provider_type ON public.llm_provider_configs USING btree (provider_type);


--
-- Name: idx_mcp_credentials_token_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_credentials_token_hash ON public.mcp_credentials USING btree (token_hash);


--
-- Name: idx_mcp_credentials_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_credentials_user ON public.mcp_credentials USING btree (user_id);


--
-- Name: idx_role_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_name ON public.roles USING btree (name);


--
-- Name: idx_shared_ioc_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shared_ioc_investigation ON public.shared_iocs USING btree (investigation_id);


--
-- Name: idx_shared_ioc_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shared_ioc_type ON public.shared_iocs USING btree (ioc_type);


--
-- Name: idx_shared_ioc_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shared_ioc_value ON public.shared_iocs USING btree (value);


--
-- Name: idx_sketch_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sketch_case_id ON public.sketch_mappings USING btree (case_id);


--
-- Name: idx_sketch_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sketch_finding_id ON public.sketch_mappings USING btree (finding_id);


--
-- Name: idx_sketch_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sketch_id ON public.sketch_mappings USING btree (sketch_id);


--
-- Name: idx_sla_policy_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sla_policy_active ON public.sla_policies USING btree (is_active);


--
-- Name: idx_sla_policy_default; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sla_policy_default ON public.sla_policies USING btree (is_default);


--
-- Name: idx_sla_policy_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sla_policy_priority ON public.sla_policies USING btree (priority_level);


--
-- Name: idx_system_config_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_system_config_type ON public.system_config USING btree (config_type);


--
-- Name: idx_system_config_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_system_config_updated_at ON public.system_config USING btree (updated_at);


--
-- Name: idx_threat_indicators_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_indicators_last_seen ON public.threat_indicators USING btree (last_seen DESC);


--
-- Name: idx_threat_indicators_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_indicators_source ON public.threat_indicators USING btree (source);


--
-- Name: idx_threat_indicators_type_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_indicators_type_value ON public.threat_indicators USING btree (indicator_type, indicator_value);


--
-- Name: idx_threat_indicators_valid_until; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_indicators_valid_until ON public.threat_indicators USING btree (valid_until);


--
-- Name: idx_user_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_email ON public.users USING btree (email);


--
-- Name: idx_user_is_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_is_active ON public.users USING btree (is_active);


--
-- Name: idx_user_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_role_id ON public.users USING btree (role_id);


--
-- Name: idx_user_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_username ON public.users USING btree (username);


--
-- Name: idx_workflow_run_phases_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_run_phases_run_id ON public.workflow_run_phases USING btree (run_id, phase_order);


--
-- Name: idx_workflow_runs_live; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_runs_live ON public.workflow_runs USING btree (workflow_id, started_at DESC) WHERE (deleted_at IS NULL);


--
-- Name: idx_workflow_runs_started_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_runs_started_at ON public.workflow_runs USING btree (started_at DESC);


--
-- Name: idx_workflow_runs_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_runs_status ON public.workflow_runs USING btree (status) WHERE ((status)::text = ANY ((ARRAY['running'::character varying, 'failed'::character varying])::text[]));


--
-- Name: idx_workflow_runs_triggered_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_runs_triggered_by ON public.workflow_runs USING btree (triggered_by, started_at);


--
-- Name: idx_workflow_runs_workflow_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_runs_workflow_id ON public.workflow_runs USING btree (workflow_id, started_at DESC);


--
-- Name: ix_ai_decision_logs_agent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_decision_logs_agent_id ON public.ai_decision_logs USING btree (agent_id);


--
-- Name: llm_provider_default_per_type; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX llm_provider_default_per_type ON public.llm_provider_configs USING btree (provider_type) WHERE (is_default = true);


--
-- Name: uniq_findings_source_extid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uniq_findings_source_extid ON public.findings USING btree (data_source, external_id) WHERE ((data_source IS NOT NULL) AND (external_id IS NOT NULL));


--
-- Name: uniq_ip_exclusions_active_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uniq_ip_exclusions_active_ip ON public.ip_exclusions USING btree (ip) WHERE (removed_at IS NULL);


--
-- Name: uq_approval_actions_idempotency_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_approval_actions_idempotency_key ON public.approval_actions USING btree (idempotency_key) WHERE ((idempotency_key IS NOT NULL) AND ((status)::text <> 'failed'::text));


--
-- Name: uq_intake_triggers_queued_finding; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_intake_triggers_queued_finding ON public.intake_triggers USING btree (finding_id) WHERE (((state)::text = 'queued'::text) AND (finding_id IS NOT NULL));


--
-- Name: agent_events agent_events_assign_hashes; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER agent_events_assign_hashes BEFORE INSERT ON public.agent_events FOR EACH ROW EXECUTE FUNCTION public.agent_events_assign_hashes();


--
-- Name: ai_model_configs trigger_ai_model_configs_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_ai_model_configs_updated_at BEFORE UPDATE ON public.ai_model_configs FOR EACH ROW EXECUTE FUNCTION public.update_ai_model_configs_timestamp();


--
-- Name: custom_agents trigger_custom_agents_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_custom_agents_updated_at BEFORE UPDATE ON public.custom_agents FOR EACH ROW EXECUTE FUNCTION public.update_custom_agents_timestamp();


--
-- Name: integration_configs trigger_integration_configs_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_integration_configs_updated_at BEFORE UPDATE ON public.integration_configs FOR EACH ROW EXECUTE FUNCTION public.update_integration_configs_timestamp();


--
-- Name: llm_provider_configs trigger_llm_provider_configs_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_llm_provider_configs_updated_at BEFORE UPDATE ON public.llm_provider_configs FOR EACH ROW EXECUTE FUNCTION public.update_llm_provider_configs_timestamp();


--
-- Name: system_config trigger_system_config_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_system_config_updated_at BEFORE UPDATE ON public.system_config FOR EACH ROW EXECUTE FUNCTION public.update_system_config_timestamp();


--
-- Name: user_preferences trigger_user_preferences_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_user_preferences_updated_at BEFORE UPDATE ON public.user_preferences FOR EACH ROW EXECUTE FUNCTION public.update_user_preferences_timestamp();


--
-- Name: roles update_roles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON public.roles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: users update_users_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: ai_decision_logs ai_decision_logs_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_decision_logs
    ADD CONSTRAINT ai_decision_logs_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: ai_decision_logs ai_decision_logs_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_decision_logs
    ADD CONSTRAINT ai_decision_logs_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(finding_id) ON DELETE CASCADE;


--
-- Name: ai_model_configs ai_model_configs_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_model_configs
    ADD CONSTRAINT ai_model_configs_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.llm_provider_configs(provider_id) ON DELETE RESTRICT;


--
-- Name: approval_actions approval_actions_workflow_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_actions
    ADD CONSTRAINT approval_actions_workflow_run_id_fkey FOREIGN KEY (workflow_run_id) REFERENCES public.workflow_runs(run_id) ON DELETE SET NULL;


--
-- Name: case_attachments case_attachments_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_attachments
    ADD CONSTRAINT case_attachments_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_closure_info case_closure_info_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_closure_info
    ADD CONSTRAINT case_closure_info_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_comments case_comments_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_comments
    ADD CONSTRAINT case_comments_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_comments case_comments_parent_comment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_comments
    ADD CONSTRAINT case_comments_parent_comment_id_fkey FOREIGN KEY (parent_comment_id) REFERENCES public.case_comments(comment_id) ON DELETE CASCADE;


--
-- Name: case_escalations case_escalations_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_escalations
    ADD CONSTRAINT case_escalations_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_evidence case_evidence_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_evidence
    ADD CONSTRAINT case_evidence_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_findings case_findings_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_findings
    ADD CONSTRAINT case_findings_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_findings case_findings_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_findings
    ADD CONSTRAINT case_findings_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(finding_id) ON DELETE CASCADE;


--
-- Name: case_iocs case_iocs_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_iocs
    ADD CONSTRAINT case_iocs_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_metrics case_metrics_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_metrics
    ADD CONSTRAINT case_metrics_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_notifications case_notifications_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_notifications
    ADD CONSTRAINT case_notifications_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_relationships case_relationships_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_relationships
    ADD CONSTRAINT case_relationships_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_relationships case_relationships_related_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_relationships
    ADD CONSTRAINT case_relationships_related_case_id_fkey FOREIGN KEY (related_case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_slas case_slas_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_slas
    ADD CONSTRAINT case_slas_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_slas case_slas_sla_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_slas
    ADD CONSTRAINT case_slas_sla_policy_id_fkey FOREIGN KEY (sla_policy_id) REFERENCES public.sla_policies(policy_id);


--
-- Name: case_tasks case_tasks_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_tasks
    ADD CONSTRAINT case_tasks_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: case_tasks case_tasks_parent_task_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_tasks
    ADD CONSTRAINT case_tasks_parent_task_id_fkey FOREIGN KEY (parent_task_id) REFERENCES public.case_tasks(task_id) ON DELETE CASCADE;


--
-- Name: case_watchers case_watchers_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_watchers
    ADD CONSTRAINT case_watchers_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: chat_messages chat_messages_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT chat_messages_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.conversations(id) ON DELETE CASCADE;


--
-- Name: episodic_verdict_sources episodic_verdict_sources_verdict_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.episodic_verdict_sources
    ADD CONSTRAINT episodic_verdict_sources_verdict_id_fkey FOREIGN KEY (verdict_id) REFERENCES public.episodic_verdicts(id) ON DELETE CASCADE;


--
-- Name: finding_mitre_predictions finding_mitre_predictions_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_mitre_predictions
    ADD CONSTRAINT finding_mitre_predictions_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(finding_id) ON DELETE CASCADE;


--
-- Name: investigation_logs investigation_logs_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_logs
    ADD CONSTRAINT investigation_logs_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(investigation_id) ON DELETE CASCADE;


--
-- Name: investigations investigations_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigations
    ADD CONSTRAINT investigations_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE SET NULL;


--
-- Name: mcp_credentials mcp_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_credentials
    ADD CONSTRAINT mcp_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: shared_iocs shared_iocs_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_iocs
    ADD CONSTRAINT shared_iocs_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(investigation_id) ON DELETE CASCADE;


--
-- Name: sketch_mappings sketch_mappings_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sketch_mappings
    ADD CONSTRAINT sketch_mappings_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- Name: sketch_mappings sketch_mappings_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sketch_mappings
    ADD CONSTRAINT sketch_mappings_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(finding_id) ON DELETE CASCADE;


--
-- Name: users users_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(role_id);


--
-- Name: workflow_run_phases workflow_run_phases_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_run_phases
    ADD CONSTRAINT workflow_run_phases_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.workflow_runs(run_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


