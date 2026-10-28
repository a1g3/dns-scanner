--
-- PostgreSQL database dump
--

-- Dumped from database version 18.3
-- Dumped by pg_dump version 18.6

-- Started on 2026-10-27 21:26:21 EDT

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 219 (class 1259 OID 16483)
-- Name: Domains; Type: TABLE; Schema: public; Owner: research
--

CREATE TABLE public."Domains" (
    "Domain" text NOT NULL,
    "GovernmentType" text NOT NULL,
    "Organization" text NOT NULL,
    "Location" text NOT NULL,
    "Note" text NOT NULL,
    "ImportLog" text NOT NULL,
    "State" text
);


ALTER TABLE public."Domains" OWNER TO research;

--
-- TOC entry 220 (class 1259 OID 16494)
-- Name: ImportLog; Type: TABLE; Schema: public; Owner: research
--

CREATE TABLE public."ImportLog" (
    "Domain" text NOT NULL,
    "FirstSeen" date NOT NULL,
    "LastSeen" date
);


ALTER TABLE public."ImportLog" OWNER TO research;

--
-- TOC entry 221 (class 1259 OID 16501)
-- Name: Runs; Type: TABLE; Schema: public; Owner: research
--

CREATE TABLE public."Runs" (
    "Name" text NOT NULL,
    "Start" timestamp with time zone,
    "End" timestamp with time zone,
    "SortOrder" integer NOT NULL
);


ALTER TABLE public."Runs" OWNER TO research;

--
-- TOC entry 222 (class 1259 OID 16508)
-- Name: Scans; Type: TABLE; Schema: public; Owner: research
--

CREATE TABLE public."Scans" (
    "Domain" text NOT NULL,
    "Scanner" text NOT NULL,
    "Region" text NOT NULL,
    "Timestamp" timestamp with time zone NOT NULL,
    "Results" json NOT NULL,
    "NewResults" json
);


ALTER TABLE public."Scans" OWNER TO research;

-- Completed on 2026-10-27 21:26:24 EDT

--
-- PostgreSQL database dump complete
--

