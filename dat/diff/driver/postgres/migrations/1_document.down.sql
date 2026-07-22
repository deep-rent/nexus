-- Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- NOTE: This file documents the expected schema of the diff synchronization
-- store's bookkeeping objects and is NOT executed by the driver. It serves
-- as reference material only: applications own their schema migrations and
-- must provision (and adapt) these objects themselves.

-- Drops the bookkeeping objects of the diff synchronization engine in
-- reverse creation order; indexes and foreign keys drop implicitly with
-- their tables. The application-owned users and teams tables are untouched.
DROP TABLE IF EXISTS "public"."document_shares";
DROP TABLE IF EXISTS "public"."document_state";
DROP TABLE IF EXISTS "public"."document_tombstones";
DROP TABLE IF EXISTS "public"."document_mutations";
DROP SEQUENCE IF EXISTS "public"."document_seq";
