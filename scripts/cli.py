import argparse
import os
import pandas as pd
import re
import utils
import datasets as data
import normalize as norm
import github_data
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent))
from lib.github_cache import GithubCache
import csv
import features

import warnings

warnings.simplefilter(action="ignore", category=FutureWarning)


def transform_to_commits(df):
    rows = []
    for _, row in df.iterrows():
        chain = list(row["chain"])
        patch_type = "MULTI" if len(chain) > 1 else "SINGLE"
        for commit in chain:
            new_row = row.copy()
            new_row["commit_href"] = commit
            new_row["project"] = "/".join(commit.split("/")[0:5])
            sha = re.sub(r"http(s)?://github.com/.*/commit(s)?/", "", commit)
            new_row["commit_sha"] = sha
            new_row["patch"] = patch_type
            rows.append(new_row)
    return pd.DataFrame(rows)


def process_sources(folder):

    config = utils.load_config("config/github.json")
    git = utils.get_token(config)

    dfs = {
        source: pd.read_csv(f"sources/{source}.csv", escapechar="\\")
        for source in ("nvd", "osv")
    }

    for df in dfs:
        dfs[df]["dataset"] = df

    # Sources
    osv, nvd = (
        data.OSV(dfs["osv"]),
        data.NVD(dfs["nvd"]),
    )

    osv.prepare()
    osv.normalize()
    osv.df["chain"] = osv.df["chain"].apply(
        lambda chain: norm.normalize_sha(git, config, chain)
    )
    osv.df = transform_to_commits(osv.df)
    osv.df.to_csv(
        f"{folder}/osv.csv",
        quoting=csv.QUOTE_NONNUMERIC,
        escapechar="\\",
        doublequote=False,
        index=False,
    )

    nvd.prepare()
    nvd.normalize()
    nvd.df["chain"] = nvd.df["chain"].apply(
        lambda chain: norm.normalize_sha(git, config, chain)
    )
    nvd.df = transform_to_commits(nvd.df)
    nvd.df.to_csv(
        f"{folder}/nvd.csv",
        quoting=csv.QUOTE_NONNUMERIC,
        escapechar="\\",
        doublequote=False,
        index=False,
    )


def merge_sources(folder):
    dfs = []
    for source in ("cve-details", "osv", "nvd"):
        path = f"commits/{source}.csv"
        if os.path.exists(path):
            dfs.append(pd.read_csv(path, escapechar="\\"))
        else:
            print(f"Skipping {path} (not found)")
    if not dfs:
        print("No source files found!")
        return
    df = pd.concat(dfs, ignore_index=True)
    print(f"Total number of entries: {len(df)}")
    df.to_csv(
        f"{folder}/sources_commits.csv",
        quoting=csv.QUOTE_NONNUMERIC,
        escapechar="\\",
        doublequote=False,
        index=False,
    )


def get_metadata(fin, folder):
    df = pd.read_csv(fin, escapechar="\\")

    if "message" in df.columns:
        check_col = "files" if "files" in df.columns else "message"
        remaining = len(df[~pd.notnull(df[check_col])])
        print(f"{remaining} entries to go out of {len(df)}")
    else:
        print(f"{len(df)} entries to go")

    config = utils.load_config("config/github.json")
    git = utils.get_token(config)
    cache_dir = _Path(__file__).resolve().parent.parent / "data" / "github_cache"
    cache = GithubCache(cache_dir)
    sha_cache = {}

    fout = f"{folder}/sources_commits_metadata.csv"
    fout_files = f"{folder}/files_raw.csv"

    if "message" in df.columns:
        repos = set(df[~pd.notnull(df["message"])]["project"])
    else:
        repos = set(df["project"])

    all_files_rows = []

    for repo in repos:

        print(f"Getting the metadata from project {repo}...")
        git, df, files_rows = github_data.metadata(
            repo, df, git, config,
            cache=cache, sha_cache=sha_cache,
        )
        all_files_rows.extend(files_rows)

        if "message" in df.columns:
            print(f"{len(df[~pd.notnull(df['additions'])])} entries to go")
        else:
            print(f"{len(df)} entries to go")

        df.to_csv(
            fout,
            quoting=csv.QUOTE_NONNUMERIC,
            escapechar="\\",
            doublequote=False,
            index=False,
        )

    if all_files_rows:
        pd.DataFrame(all_files_rows).to_csv(
            fout_files,
            quoting=csv.QUOTE_NONNUMERIC,
            escapechar="\\",
            doublequote=False,
            index=False,
        )
    print(f"Cache stats: {cache.stats.summary()}")


def clean_data(fin, fout, col="message"):
    df = pd.read_csv(fin, escapechar="\\")

    if col == "files":
        vuln_ids = list(df[~pd.notnull(df["files"])]["vuln_id"].unique())
        df.drop(df[df["vuln_id"].isin(vuln_ids)].index, inplace=True)
    elif col == "message":
        vuln_ids = list(df[~pd.notnull(df["message"])]["vuln_id"].unique())
        df.drop(df[df["vuln_id"].isin(vuln_ids)].index, inplace=True)

    df.to_csv(
        fout,
        quoting=csv.QUOTE_NONNUMERIC,
        escapechar="\\",
        doublequote=False,
        index=False,
    )


def filter_data(fin, fout, col, value, nodups):
    def if_lang(value, x):
        if pd.notna(x):
            if value in eval(x):
                return 1    
        return 0
    df = pd.read_csv(fin, escapechar="\\")
    
    if col == 'patch':
        df = df[df[col] == value]
    elif col == 'language':
        df[value] = df[col].apply(lambda x: if_lang(value, x))
        df = df[df[value] == 1]
        del df[value]

    if nodups:
        keys = list(df.keys())
        keys.remove("dataset")
        df = df.drop_duplicates(subset=keys)
            
    df.to_csv(
        fout,
        quoting=csv.QUOTE_NONNUMERIC,
        escapechar="\\",
        doublequote=False,
        index=False,
    )


def collect_feature(fin, fout, feature):

    df = pd.read_csv(fin, escapechar="\\")

    if feature == "extension":
        df["files_extension"] = df["files"].apply(
            lambda x: features.get_files_extension(x)
        )
    elif feature == "language":
        df["files_extension"] = df["files"].apply(
            lambda x: features.get_files_extension(x)
        )
        df["language"] = df["files_extension"].apply(lambda x: features.get_language(x))

        df["files"] = df["files"].apply(lambda x: features.add(x))

    df.to_csv(
        fout,
        quoting=csv.QUOTE_NONNUMERIC,
        escapechar="\\",
        doublequote=False,
        index=False,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="dataset manipulation and reproduction CLI"
    )
    parser.add_argument(
        "--task",
        dest="format",
        choices=["process", "merge", "metadata", "clean", "collection", "filter"],
    )
    parser.add_argument(
        "--folder", type=str, metavar="output folder", help="base folder"
    )
    parser.add_argument("--fin", type=str, metavar="input file", help="base file")
    parser.add_argument("--fout", type=str, metavar="output file", help="base file")
    parser.add_argument("--feature", dest="feature", choices=["extension", "language"])
    parser.add_argument("--col", dest="col", choices=["files", "message", "patch", "language"])
    parser.add_argument("--value", metavar="value", help="cell value")
    parser.add_argument("--nodups", default=False, action="store_true")

    args = parser.parse_args()

    if args.format == "process":
        if args.folder:
            process_sources(args.folder)
    elif args.format == "merge":
        if args.folder:
            merge_sources(args.folder)
    elif args.format == "metadata":
        if args.folder and args.fin:
            get_metadata(args.fin, args.folder)
    elif args.format == "clean":
        if args.fout and args.fin and args.col in ("files", "message"):
            clean_data(args.fin, args.fout, col=args.col)
    elif args.format == "filter":
        if args.fout and args.fin and args.col in ("patch", "language") and args.value:
            filter_data(args.fin, args.fout, args.col, args.value, args.nodups)
    elif args.format == "collection":
        if args.fout and args.fin and args.feature in ("extension", "language"):
            collect_feature(args.fin, args.fout, args.feature)
    else:
        print("Something is wrong. Verify your parameters")
