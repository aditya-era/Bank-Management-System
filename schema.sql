-- Original tables (unchanged). New columns are added by database.py migrations,
-- so an existing bank.db keeps all its users and transactions.
create table if not exists users(
    id integer primary key autoincrement,
    username text not null,
    password text not null,
    balance real default 0
);
create table if not exists transactions(
    id integer primary key autoincrement,
    user_id integer,
    type text,
    amount real,
    date timestamp default current_timestamp
);
