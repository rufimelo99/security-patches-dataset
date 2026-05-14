import ast
import json
import sys
import time

import pandas as pd
import numpy as np
import utils

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

from github import RateLimitExceededException
from github import UnknownObjectException

from pathlib import Path as _Path
import sys as _sys
_sys.path.insert(0, str(_Path(__file__).resolve().parent))
from lib.commit_fetcher import fetch_commit

def load_missing_commits(df, repo):
    if 'files' in df.columns:
        print(f"some entries already completed")
        commits_list = df[(df['project'] == repo) & (~pd.notnull(df['files']))]
    else:
        print(f"no entries completed; starting from 0")
        commits_list = df[df['project'] == repo]
    return commits_list

def sort_chain(repo, chain, *, git=None, config=None, cache=None, sha_cache=None):
    if sha_cache is None:
        sha_cache = {}
    chain_list = list(chain) if isinstance(chain, (set, list)) else list(ast.literal_eval(chain))
    rows = []
    for commit in chain_list:
        try:
            sha = commit.split('/')[-1]
            gcommit = fetch_commit(
                repo, sha, git=git, config=config,
                cache=cache, sha_cache=sha_cache,
            )
            author = gcommit.commit.author
            rows.append({'commit': gcommit, 'datetime': author.date})
        except Exception as e:
            print("Unexpected error: {}".format(e))
            return None, None

    df = pd.DataFrame(rows)
    df = df.drop_duplicates()
    df = df.sort_values(by='datetime', ascending=True)
    return list(df['commit']), list(df['datetime'])
        

def get_parents(chain_commit):
    parents = set([commit.sha for commit in chain_commit.commit.parents])
    return parents

def set_commits_info(df, idx, last_commit, chain_datetime, chain_idx):
    parents = set([commit.sha for commit in last_commit.commit.parents])
    df.loc[idx, 'before_first_fix_commit'] = str(parents)
    df.loc[idx, 'last_fix_commit'] = last_commit.commit.sha
    df.loc[idx, 'chain_ord_pos'] = chain_idx + 1
    df.loc[idx, 'commit_datetime'] = chain_datetime[chain_idx].isoformat() + "Z"


def metadata(repo, df, git, config, files_rows=None, *, cache=None, sha_cache=None):
    if files_rows is None:
        files_rows = []

    # get owner and project
    if not pd.notna(repo):
        return git, df, files_rows
    owner, project = repo.split('/')[3::]

    # get entries to complete per repo
    commits_list = load_missing_commits(df, repo)

    try:
        repo = git.get_repo('{}/{}'.format(owner, project))
    except RateLimitExceededException:
        git = utils.get_token(config)
    except UnknownObjectException:
        print(f"🚨 Repo not found. Skipping {owner}/{project} ...")
        return git, df, files_rows

    for idx, row in commits_list.iterrows():
        chain_ord, chain_datetime = sort_chain(
            repo, row['chain'],
            git=git, config=config, cache=cache, sha_cache=sha_cache,
        )
        
        # FIXME: one of the source vulns still has the href in 
        # the commit_sha column when it reaches here. For some
        # reason this is not fixed in the normalization phase.
        # Find why!
        if 'http' in row['commit_sha']:
            row['commit_sha'] = row['commit_sha'].split('/')[-1]
              
        if not chain_ord and not chain_datetime:
            print(f"🚨 Skipping {row['vuln_id']} ...")
            continue

        try:
            chain_ord_sha = [commit.commit.sha for commit in chain_ord]
            df.loc[idx, 'chain_ord'] = str(chain_ord_sha)
            if len(chain_ord) == 1:
                last_commit = chain_ord[0]
                df.loc[idx, 'before_first_fix_commit'] = json.dumps([p.sha for p in last_commit.commit.parents])
                chain_idx = chain_ord_sha.index(row['commit_sha'])
                set_commits_info(df, idx, last_commit, chain_datetime, chain_idx)
            else:
                first_commit, last_commit = chain_ord[0], chain_ord[-1]
                df.loc[idx, 'before_first_fix_commit'] = json.dumps([p.sha for p in first_commit.commit.parents])
                chain_idx = chain_ord_sha.index(row['commit_sha'])
                set_commits_info(df, idx, last_commit, chain_datetime, chain_idx)

            commit = chain_ord[chain_idx]
            df.loc[idx, 'message'] = commit.commit.message.strip()
            df.loc[idx, 'author'] = commit.commit.author.name.strip()
            df.loc[idx, 'author_date'] = commit.commit.author.date.isoformat() + "Z"
            df.loc[idx, 'committer_name'] = commit.commit.committer.name.strip()
            df.loc[idx, 'committer_date'] = commit.commit.committer.date.isoformat() + "Z"
            df.loc[idx, 'is_merge'] = len(commit.commit.parents) > 1
            verification = getattr(commit.commit, 'verification', None)
            df.loc[idx, 'is_signed'] = bool(verification.verified) if verification else False
            df.loc[idx, 'parents'] = json.dumps([p.sha for p in commit.commit.parents])

            comment_list = [
                {"author": c.user.login, "date": c.created_at.isoformat() + "Z", "body": c.body.strip()}
                for c in commit.get_comments()
            ]
            df.loc[idx, 'comments'] = json.dumps(comment_list) if comment_list else np.nan

            df.loc[idx, 'additions'] = int(commit.stats.additions)
            df.loc[idx, 'deletions'] = int(commit.stats.deletions)
            df.loc[idx, 'files_changed'] = int(commit.stats.total)

            for f in commit.files:
                files_rows.append({
                    "commit_sha": row['commit_sha'],
                    "filename": f.filename,
                    "additions": f.additions,
                    "deletions": f.deletions,
                    "changes": f.changes,
                    "status": f.status,
                    "previous_filename": getattr(f, 'previous_filename', None),
                    "patch": f.patch.strip() if f.patch else None,
                })

        except RateLimitExceededException:
            git = utils.get_token(config)

    return git, df, files_rows
