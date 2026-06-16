# accounts

The central **account + credential-vault** service for [berkkarabacak.com](https://berkkarabacak.com): one login (email/password or Google SSO) shared across all apps, and an encrypted store of your saved Jira sites + API tokens. FastAPI; data in SQLite, tokens Fernet-encrypted at rest. Needs [bk-common](https://github.com/berkkarabacak/bk-common) on `PYTHONPATH`. MIT licensed.
