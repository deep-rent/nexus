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

-- Drops the bookkeeping objects of the diff synchronization engine in
-- reverse creation order; indexes drop implicitly with their tables.
DROP TABLE IF EXISTS "public"."diff_shares";
DROP TABLE IF EXISTS "public"."diff_state";
DROP TABLE IF EXISTS "public"."diff_tombstones";
DROP TABLE IF EXISTS "public"."diff_mutations";
DROP SEQUENCE IF EXISTS "public"."diff_seq";
