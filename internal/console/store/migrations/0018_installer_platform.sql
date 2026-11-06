-- Installers for Linux too (self-extracting .run): the platform of each.

ALTER TABLE agent_installers ADD COLUMN platform text NOT NULL DEFAULT 'windows/amd64';
