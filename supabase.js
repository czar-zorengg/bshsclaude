/* ============================================================
   BSHS LOST AND FOUND HUB
   Supabase client configuration

   This is the ONLY file you need to edit to connect the site
   to your Supabase project. Paste your values below.

   SUPABASE_URL      -> Supabase Dashboard -> Project Settings -> API -> Project URL
   SUPABASE_ANON_KEY -> Supabase Dashboard -> Project Settings -> API -> anon / publishable key

   NEVER put your service_role key here. This file is public
   (it ships to every visitor's browser), so only the anon /
   publishable key belongs here. Row Level Security (RLS) in
   schema.sql is what actually protects your data.
   ============================================================ */

const SUPABASE_URL = "https://cuhdvpqgbjzkmrinbyjh.supabase.co";
const SUPABASE_ANON_KEY = "sb_publishable_NI2lEYRyMo6u8tZMF3RHNA_so3UxL30";

const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
