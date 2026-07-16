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

-- Bookkeeping objects of the diff synchronization engine, using the default
-- object names. Statements stay idempotent (IF NOT EXISTS) because Store.Init
-- executes this file directly on every startup in migrate-less setups.

-- The global sequence ordering the patch feed.
CREATE SEQUENCE IF NOT EXISTS "public"."diff_seq" CACHE 1;

-- The mutation deduplication table.
CREATE TABLE IF NOT EXISTS "public"."diff_mutations" (
  id         UUID PRIMARY KEY,
  user_id    UUID NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS diff_mutations_applied_at
  ON "public"."diff_mutations" (applied_at);

-- The tombstone table recording deletions across all entity types.
CREATE TABLE IF NOT EXISTS "public"."diff_tombstones" (
  type       TEXT NOT NULL,
  id         UUID NOT NULL,
  user_id    UUID NOT NULL,
  team_id    UUID,
  hlc        BIGINT NOT NULL,
  seq        BIGINT NOT NULL,
  deleted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (type, id)
);
CREATE INDEX IF NOT EXISTS diff_tombstones_user_seq
  ON "public"."diff_tombstones" (user_id, seq);
CREATE INDEX IF NOT EXISTS diff_tombstones_team_seq
  ON "public"."diff_tombstones" (team_id, seq) WHERE team_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS diff_tombstones_deleted_at
  ON "public"."diff_tombstones" (deleted_at);

-- The state table seeded with the retention floor.
CREATE TABLE IF NOT EXISTS "public"."diff_state" (
  key TEXT PRIMARY KEY,
  seq BIGINT NOT NULL
);
INSERT INTO "public"."diff_state" (key, seq)
  VALUES ('floor', 0) ON CONFLICT DO NOTHING;

-- The table backing the reserved "share" entity type.
CREATE TABLE IF NOT EXISTS "public"."diff_shares" (
  id      UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  team_id UUID NOT NULL,
  hlc     BIGINT NOT NULL,
  seq     BIGINT NOT NULL,
  UNIQUE (user_id, team_id)
);
CREATE INDEX IF NOT EXISTS diff_shares_user_seq
  ON "public"."diff_shares" (user_id, seq);
CREATE INDEX IF NOT EXISTS diff_shares_team_seq
  ON "public"."diff_shares" (team_id, seq);
