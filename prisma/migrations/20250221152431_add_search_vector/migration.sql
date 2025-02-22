/*
  Warnings:

  - Added the required column `search_vector` to the `Template` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Template" ADD COLUMN     "search_vector" tsvector NOT NULL;
