-- Maysar v2. Install once in a NEW Supabase project using its SQL editor.
-- No service key belongs in the browser. All browser access uses RLS.
begin;
create schema if not exists maysar_private;
revoke all on schema maysar_private from public, anon;
grant usage on schema maysar_private to authenticated;

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '', phone text not null default '',
  role text not null default 'client' check (role in ('client','advisor','admin')),
  created_at timestamptz not null default now()
);
create table public.companies (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references public.profiles(id) on delete cascade,
  data jsonb not null default '{}' check(jsonb_typeof(data)='object'),
  assessment jsonb not null default '{}' check(jsonb_typeof(assessment)='object'),
  updated_at timestamptz not null default now()
);
create table public.applications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  company_id uuid not null references public.companies(id),
  product text not null, amount numeric(18,3) not null check(amount>0 and amount<=1000000000),
  country text not null check(country in ('ae','sa','kw','qa','bh','om')),
  currency text not null check(currency in ('AED','SAR','KWD','QAR','BHD','OMR')),
  answers jsonb not null, company_snapshot jsonb not null,
  lender_ids jsonb not null default '[]' check(jsonb_typeof(lender_ids)='array'),
  status text not null default 'review' check(status in ('review','needs_info','ready','submitted','offer','contract','funded','declined','withdrawn')),
  reference text not null default '',
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table public.documents (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references public.profiles(id) on delete cascade,
  type text not null check(type in ('license','bank','invoice','contract','quotation','payroll','project','financial','other')),
  name text not null check(length(name) between 1 and 255),
  mime text not null check(mime in ('application/pdf','image/png','image/jpeg')),
  size bigint not null check(size>0 and size<=10485760),
  status text not null default 'uploaded' check(status in ('uploaded','reviewed','rejected')),
  object_path text not null unique,
  created_at timestamptz not null default now(),
  check(object_path=user_id::text||'/'||id::text||case mime when 'application/pdf' then '.pdf' when 'image/png' then '.png' else '.jpg' end)
);
create table public.application_events (
  id uuid primary key default gen_random_uuid(), application_id uuid not null references public.applications(id) on delete cascade,
  status text not null, note text not null check(length(note) between 1 and 2000), reference text not null default '',
  created_at timestamptz not null default now()
);
create table public.messages (
  id uuid primary key default gen_random_uuid(), application_id uuid not null references public.applications(id) on delete cascade,
  user_id uuid not null references public.profiles(id), sender_role text not null default 'client',
  body text not null check(length(trim(body)) between 1 and 4000), created_at timestamptz not null default now()
);
create table public.offers (
  id uuid primary key default gen_random_uuid(), application_id uuid not null references public.applications(id) on delete cascade,
  provider_name text not null check(length(trim(provider_name)) between 1 and 140),
  amount numeric(18,3) not null check(amount>0 and amount<=1000000000),
  months integer not null check(months between 1 and 360), monthly_payment numeric(18,3) not null check(monthly_payment>0 and monthly_payment<=1000000000),
  fees numeric(18,3) not null default 0 check(fees>=0 and fees<amount),
  security text not null default '' check(length(security)<=300), reference text not null check(length(trim(reference)) between 1 and 200),
  valid_until date, demo boolean not null default false check(demo=false), created_at timestamptz not null default now()
);
create table public.offer_acceptances (
  id uuid primary key default gen_random_uuid(), application_id uuid not null references public.applications(id) on delete cascade,
  offer_id uuid not null references public.offers(id), user_id uuid not null references public.profiles(id),
  created_at timestamptz not null default now(), unique(application_id,user_id)
);
create table public.reports (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references public.profiles(id) on delete cascade,
  data jsonb not null check(jsonb_typeof(data)='object' and (data->>'kind') is not distinct from 'preliminary' and (data->>'payment_status') is not distinct from 'not_charged'),
  created_at timestamptz not null default now()
);
create table public.consents (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references public.profiles(id) on delete cascade,
  application_id uuid not null references public.applications(id) on delete cascade,
  lender_ids jsonb not null, purpose text not null, created_at timestamptz not null default now()
);
create table public.directory_overrides (
  id text primary key check(id in ('beehive-term','beehive-invoice','crediblex','fundingsouq-ae','numou','lendo','tameed','manafa')),
  criteria jsonb not null check(jsonb_typeof(criteria)='object' and coalesce(criteria->>'url','') ~ '^https://[^[:space:]]+$' and (criteria-array['minMonths','minRevenue','minAmount','maxAmount','url','reviewed'])='{}'::jsonb),
  updated_by uuid not null references public.profiles(id), updated_at timestamptz not null default now()
);

-- A private definer helper avoids recursive profile RLS. No caller-supplied user ID.
create function maysar_private.is_staff() returns boolean
language sql stable security definer set search_path=''
as $$ select auth.uid() is not null and exists(select 1 from public.profiles where id=auth.uid() and role in ('advisor','admin')); $$;
revoke all on function maysar_private.is_staff() from public,anon;
grant execute on function maysar_private.is_staff() to authenticated;

create function maysar_private.new_profile() returns trigger
language plpgsql security definer set search_path=''
as $$ begin
  insert into public.profiles(id,display_name) values(new.id,left(coalesce(new.raw_user_meta_data->>'display_name',''),140));
  return new;
end; $$;
revoke all on function maysar_private.new_profile() from public,anon,authenticated;
create trigger maysar_new_profile after insert on auth.users for each row execute function maysar_private.new_profile();

create function maysar_private.message_author() returns trigger
language plpgsql security definer set search_path=''
as $$ begin
  if auth.uid() is null or new.user_id<>auth.uid() then raise exception 'not_authorized'; end if;
  if not exists(select 1 from public.applications a where a.id=new.application_id and (a.user_id=auth.uid() or maysar_private.is_staff())) then raise exception 'not_authorized'; end if;
  select p.role into new.sender_role from public.profiles p where p.id=auth.uid();
  new.created_at:=now(); return new;
end; $$;
revoke all on function maysar_private.message_author() from public,anon,authenticated;
create trigger maysar_message_author before insert on public.messages for each row execute function maysar_private.message_author();

create function maysar_private.acceptance_check() returns trigger
language plpgsql security definer set search_path=''
as $$ begin
  if auth.uid() is null or new.user_id<>auth.uid() or not exists(
    select 1 from public.offers o join public.applications a on a.id=o.application_id
    where o.id=new.offer_id and a.id=new.application_id and a.user_id=auth.uid()
      and a.status in ('offer','contract') and (o.valid_until is null or o.valid_until>=(now() at time zone 'Asia/Dubai')::date)
  ) then raise exception 'invalid_offer_selection'; end if;
  new.created_at:=now(); return new;
end; $$;
revoke all on function maysar_private.acceptance_check() from public,anon,authenticated;
create trigger maysar_acceptance_check before insert on public.offer_acceptances for each row execute function maysar_private.acceptance_check();

-- Atomic transaction owns application, consent and initial event. Clients cannot
-- INSERT these tables directly or forge a status/audit event.
create function public.submit_application(p_answers jsonb,p_company_id uuid,p_lender_ids jsonb,p_consent boolean)
returns uuid language plpgsql security definer set search_path=''
as $$ declare c public.companies; result uuid; cur text; begin
  if auth.uid() is null or p_consent is distinct from true then raise exception 'consent_required'; end if;
  select * into c from public.companies where id=p_company_id and user_id=auth.uid();
  if not found then raise exception 'company_required'; end if;
  if coalesce(c.data->>'name','')='' or coalesce(c.data->>'license','')='' or coalesce(c.data->>'email','')='' or coalesce(c.data->>'contact_name','')='' or coalesce(c.data->>'phone','')='' then raise exception 'company_incomplete'; end if;
  if p_answers is null or jsonb_typeof(p_answers)<>'object' then raise exception 'invalid_assessment'; end if;
  if not (p_answers ?& array['country','product','sector','months','revenue','obligations','amount','purpose']) then raise exception 'invalid_assessment'; end if;
  if coalesce(p_answers->>'country','') not in ('ae','sa','kw','qa','bh','om') or coalesce(p_answers->>'product','') not in ('working','invoice','purchase','equipment','payroll','guarantee','property','explore') or coalesce(p_answers->>'sector','') not in ('trade','tech','industry','health','hospitality','logistics','property','other') then raise exception 'invalid_assessment'; end if;
  if coalesce(p_answers->>'months','')!~'^\d+(\.\d+)?$' or coalesce(p_answers->>'revenue','')!~'^\d+(\.\d+)?$' or coalesce(p_answers->>'obligations','')!~'^\d+(\.\d+)?$' or coalesce(p_answers->>'amount','')!~'^\d+(\.\d+)?$' then raise exception 'invalid_assessment'; end if;
  if (p_answers->>'months')::numeric>1200 or (p_answers->>'revenue')::numeric>1000000000000 or (p_answers->>'obligations')::numeric>10000000000 or (p_answers->>'amount')::numeric<=0 or (p_answers->>'amount')::numeric>1000000000 or length(trim(coalesce(p_answers->>'purpose',''))) not between 1 and 1500 then raise exception 'invalid_assessment'; end if;
  if p_lender_ids is null or jsonb_typeof(p_lender_ids)<>'array' or jsonb_array_length(p_lender_ids)>8 then raise exception 'invalid_providers'; end if;
  if exists(select 1 from jsonb_array_elements_text(p_lender_ids) x where x is null or x not in ('beehive-term','beehive-invoice','crediblex','fundingsouq-ae','numou','lendo','tameed','manafa')) then raise exception 'invalid_providers'; end if;
  cur:=case p_answers->>'country' when 'ae' then 'AED' when 'sa' then 'SAR' when 'kw' then 'KWD' when 'qa' then 'QAR' when 'bh' then 'BHD' else 'OMR' end;
  insert into public.applications(user_id,company_id,product,amount,country,currency,answers,company_snapshot,lender_ids)
    values(auth.uid(),c.id,p_answers->>'product',(p_answers->>'amount')::numeric,p_answers->>'country',cur,p_answers,c.data,p_lender_ids) returning id into result;
  insert into public.consents(user_id,application_id,lender_ids,purpose) values(auth.uid(),result,p_lender_ids,'application_review_and_selected_provider_sharing');
  insert into public.application_events(application_id,status,note) values(result,'review','Internal review created. Not sent to a finance provider.');
  return result;
end; $$;
revoke all on function public.submit_application(jsonb,uuid,jsonb,boolean) from public,anon;
grant execute on function public.submit_application(jsonb,uuid,jsonb,boolean) to authenticated;

create function public.change_application_status(p_id uuid,p_status text,p_note text,p_reference text default '')
returns void language plpgsql security definer set search_path=''
as $$ declare current_status text; allowed text[]; begin
  if auth.uid() is null or not maysar_private.is_staff() then raise exception 'not_authorized'; end if;
  select status into current_status from public.applications where id=p_id for update;
  if not found then raise exception 'not_found'; end if;
  allowed:=case current_status
    when 'review' then array['needs_info','ready','declined','withdrawn']
    when 'needs_info' then array['review','ready','declined','withdrawn']
    when 'ready' then array['submitted','needs_info','withdrawn']
    when 'submitted' then array['needs_info','offer','declined','withdrawn']
    when 'offer' then array['contract','needs_info','declined','withdrawn']
    when 'contract' then array['funded','needs_info','withdrawn'] else array[]::text[] end;
  if p_status is null or not p_status=any(allowed) then raise exception 'invalid_transition'; end if;
  if length(trim(coalesce(p_note,''))) not between 1 and 2000 then raise exception 'note_required'; end if;
  if length(coalesce(p_reference,''))>200 or (p_status in ('submitted','funded') and length(trim(coalesce(p_reference,'')))=0) then raise exception 'reference_required'; end if;
  if p_status='submitted' and not exists(select 1 from public.consents where application_id=p_id and jsonb_array_length(lender_ids)>0) then raise exception 'selected_provider_consent_required'; end if;
  if p_status='offer' and not exists(select 1 from public.offers where application_id=p_id) then raise exception 'offer_required'; end if;
  if p_status='contract' and not exists(select 1 from public.offer_acceptances where application_id=p_id) then raise exception 'offer_selection_required'; end if;
  update public.applications set status=p_status,reference=coalesce(p_reference,''),updated_at=now() where id=p_id;
  insert into public.application_events(application_id,status,note,reference) values(p_id,p_status,p_note,coalesce(p_reference,''));
end; $$;
revoke all on function public.change_application_status(uuid,text,text,text) from public,anon;
grant execute on function public.change_application_status(uuid,text,text,text) to authenticated;

alter table public.profiles enable row level security;
alter table public.companies enable row level security;
alter table public.applications enable row level security;
alter table public.documents enable row level security;
alter table public.application_events enable row level security;
alter table public.messages enable row level security;
alter table public.offers enable row level security;
alter table public.offer_acceptances enable row level security;
alter table public.reports enable row level security;
alter table public.consents enable row level security;
alter table public.directory_overrides enable row level security;

revoke all on public.profiles,public.companies,public.applications,public.documents,public.application_events,public.messages,public.offers,public.offer_acceptances,public.reports,public.consents,public.directory_overrides from anon,authenticated;
grant select on public.profiles,public.companies,public.applications,public.documents,public.application_events,public.messages,public.offers,public.offer_acceptances,public.reports,public.consents,public.directory_overrides to authenticated;
grant update(display_name,phone) on public.profiles to authenticated;
grant insert on public.companies,public.documents,public.offers,public.offer_acceptances,public.reports,public.directory_overrides to authenticated;
grant insert(application_id,user_id,body) on public.messages to authenticated;
grant update(user_id,data,assessment,updated_at) on public.companies to authenticated;
grant update(id,criteria,updated_by,updated_at) on public.directory_overrides to authenticated;
grant delete on public.documents to authenticated;

create policy profile_read on public.profiles for select to authenticated using(id=(select auth.uid()) or (select maysar_private.is_staff()));
create policy profile_edit on public.profiles for update to authenticated using(id=(select auth.uid())) with check(id=(select auth.uid()));
create policy company_read on public.companies for select to authenticated using(user_id=(select auth.uid()) or (select maysar_private.is_staff()));
create policy company_insert on public.companies for insert to authenticated with check(user_id=(select auth.uid()));
create policy company_edit on public.companies for update to authenticated using(user_id=(select auth.uid())) with check(user_id=(select auth.uid()));
create policy application_read on public.applications for select to authenticated using(user_id=(select auth.uid()) or (select maysar_private.is_staff()));
create policy document_read on public.documents for select to authenticated using(user_id=(select auth.uid()) or (select maysar_private.is_staff()));
create policy document_insert on public.documents for insert to authenticated with check(user_id=(select auth.uid()) and status='uploaded');
create policy document_delete on public.documents for delete to authenticated using(user_id=(select auth.uid()));
create policy event_read on public.application_events for select to authenticated using(exists(select 1 from public.applications a where a.id=application_id and (a.user_id=(select auth.uid()) or (select maysar_private.is_staff()))));
create policy message_read on public.messages for select to authenticated using(exists(select 1 from public.applications a where a.id=application_id and (a.user_id=(select auth.uid()) or (select maysar_private.is_staff()))));
create policy message_insert on public.messages for insert to authenticated with check(user_id=(select auth.uid()) and exists(select 1 from public.applications a where a.id=application_id and (a.user_id=(select auth.uid()) or (select maysar_private.is_staff()))));
create policy offer_read on public.offers for select to authenticated using(exists(select 1 from public.applications a where a.id=application_id and (a.user_id=(select auth.uid()) or (select maysar_private.is_staff()))));
create policy offer_insert on public.offers for insert to authenticated with check((select maysar_private.is_staff()) and exists(select 1 from public.applications a where a.id=application_id and a.status in ('submitted','offer')));
create policy acceptance_read on public.offer_acceptances for select to authenticated using(user_id=(select auth.uid()) or (select maysar_private.is_staff()));
create policy acceptance_insert on public.offer_acceptances for insert to authenticated with check(user_id=(select auth.uid()));
create policy report_read on public.reports for select to authenticated using(user_id=(select auth.uid()) or (select maysar_private.is_staff()));
create policy report_insert on public.reports for insert to authenticated with check(user_id=(select auth.uid()));
create policy consent_read on public.consents for select to authenticated using(user_id=(select auth.uid()) or (select maysar_private.is_staff()));
create policy directory_read on public.directory_overrides for select to authenticated using(true);
create policy directory_insert on public.directory_overrides for insert to authenticated with check((select maysar_private.is_staff()) and updated_by=(select auth.uid()));
create policy directory_edit on public.directory_overrides for update to authenticated using((select maysar_private.is_staff())) with check((select maysar_private.is_staff()) and updated_by=(select auth.uid()));

create index applications_user on public.applications(user_id);
create index applications_company on public.applications(company_id);
create index documents_user on public.documents(user_id);
create index events_application on public.application_events(application_id);
create index messages_application on public.messages(application_id);
create index messages_author on public.messages(user_id);
create index offers_application on public.offers(application_id);
create index acceptances_offer on public.offer_acceptances(offer_id);
create index reports_user on public.reports(user_id);
create index consents_user on public.consents(user_id);
create index consents_application on public.consents(application_id);
create index overrides_author on public.directory_overrides(updated_by);

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('maysar-documents','maysar-documents',false,10485760,array['application/pdf','image/png','image/jpeg']);
create policy maysar_file_read on storage.objects for select to authenticated using(bucket_id='maysar-documents' and ((storage.foldername(name))[1]=(select auth.uid())::text or (select maysar_private.is_staff())));
create policy maysar_file_insert on storage.objects for insert to authenticated with check(bucket_id='maysar-documents' and (storage.foldername(name))[1]=(select auth.uid())::text);
create policy maysar_file_delete on storage.objects for delete to authenticated using(bucket_id='maysar-documents' and (storage.foldername(name))[1]=(select auth.uid())::text);
commit;
