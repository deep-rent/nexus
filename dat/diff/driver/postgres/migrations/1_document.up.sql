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

-- Bookkeeping objects of the diff synchronization engine, using the default
-- object names in the default schema.
--
-- The foreign keys below assume the standard application-owned
-- "public"."users" and "public"."teams" tables; adjust them if your schema
-- names differ. ON DELETE behavior is deliberately conservative:
--
--   * user_id references are RESTRICT everywhere: rows record who applied a
--     mutation, who owned a deleted document, and who granted a share.
--     Deleting a user who still has such records must be an explicit
--     offboarding flow, not an accidental cascade (and SET NULL would break
--     the feed's visibility semantics, which filter on these columns).
--   * team_id on tombstones is RESTRICT for the same reason: tombstones are
--     historical facts that team members still need to sync, and SET NULL
--     would silently reclassify them as personal deletions.
--   * team_id on shares is RESTRICT: a share grants a team access to an
--     owner's personal documents, so its members are owed a deletion when
--     the grant ends. A cascade would drop the grant silently, leaving
--     those members with phantom visibility until a forced resync. Delete a
--     team through an explicit offboarding flow (Store.OffboardTeam) that
--     buries the grants first, so the deletions reach the feed.

-- The global sequence ordering the patch feed.
CREATE SEQUENCE IF NOT EXISTS "public"."document_seq" CACHE 1;

-- The mutation deduplication table.
CREATE TABLE IF NOT EXISTS "public"."document_mutations" (
  id         UUID PRIMARY KEY,
  user_id    UUID NOT NULL
    REFERENCES "public"."users" (id) ON DELETE RESTRICT,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS document_mutations_applied_at
  ON "public"."document_mutations" (applied_at);

-- The tombstone table recording deletions across all models. The feed scan
-- filters tombstones per model and visibility branch, so the seq indexes
-- lead with the type column.
CREATE TABLE IF NOT EXISTS "public"."document_tombstones" (
  type       TEXT NOT NULL,
  id         UUID NOT NULL,
  user_id    UUID NOT NULL
    REFERENCES "public"."users" (id) ON DELETE RESTRICT,
  team_id    UUID
    REFERENCES "public"."teams" (id) ON DELETE RESTRICT,
  hlc        BIGINT NOT NULL,
  seq        BIGINT NOT NULL,
  deleted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (type, id)
);
CREATE INDEX IF NOT EXISTS document_tombstones_type_user_seq
  ON "public"."document_tombstones" (type, user_id, seq);
CREATE INDEX IF NOT EXISTS document_tombstones_type_team_seq
  ON "public"."document_tombstones" (type, team_id, seq)
  WHERE team_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS document_tombstones_deleted_at
  ON "public"."document_tombstones" (deleted_at);

-- The state table seeded with the retention floor.
CREATE TABLE IF NOT EXISTS "public"."document_state" (
  key TEXT PRIMARY KEY,
  seq BIGINT NOT NULL
);
INSERT INTO "public"."document_state" (key, seq)
  VALUES ('floor', 0) ON CONFLICT DO NOTHING;

-- The table backing the reserved "share" model.
CREATE TABLE IF NOT EXISTS "public"."document_shares" (
  id      UUID PRIMARY KEY,
  user_id UUID NOT NULL
    REFERENCES "public"."users" (id) ON DELETE RESTRICT,
  team_id UUID NOT NULL
    REFERENCES "public"."teams" (id) ON DELETE RESTRICT,
  hlc     BIGINT NOT NULL,
  seq     BIGINT NOT NULL,
  UNIQUE (user_id, team_id)
);
CREATE INDEX IF NOT EXISTS document_shares_user_seq
  ON "public"."document_shares" (user_id, seq);
CREATE INDEX IF NOT EXISTS document_shares_team_seq
  ON "public"."document_shares" (team_id, seq);
