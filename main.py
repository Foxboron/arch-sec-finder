#!/bin/python

import json
import argparse

from database import init_database


from database.nvde import \
        get_all_nvd_data, get_recent_nvd_data,\
        commit_cve

from database.nvde import NVD, WatchList


# $pkgname -> $pkgver
PACKAGES = {}


def init_packages():
    with open("packages") as f:
        for v in f.readlines():
            pkgname, pkgver = v.strip().split()
            PACKAGES[pkgname] = pkgver
    print("Parsed packages")


# # key: pkgname-pkgver
# # Metadata
# AVGS = {}




# for avg in AVGS.values():
#     fmt_avg(avg[0])



SESSION = init_database()


def refresh():
    j = get_recent_nvd_data()
    commit_cve(SESSION, j)
    print("[*] Updated Recent from NVD")

    j = get_all_nvd_data()
    commit_cve(SESSION, j)
    print("[*] Updated 2020.json from NVD")


def find_all(check_tracker=False):
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-tracker', dest='check_tracker',
                    action='store_true',
                    help='check all CVEs towards the security tracker')
    subparsers = parser.add_subparsers(dest='subcommand')
    subparsers.add_parser('refresh')
    subparsers.add_parser('find-all')
    subparsers.add_parser('grep-cpe')
    subparsers.add_parser('watch-list')
    watch_add = subparsers.add_parser('watch-add')
    watch_add.add_argument('cve', nargs='+', help='one of CVEs to be watched')
    subparsers.add_parser('watch-get')
    args = parser.parse_args()
    if args.subcommand == "refresh":
        refresh()
    elif args.subcommand == "find-all":
        find_all(check_tracker=parser.check_tracker)
    elif args.subcommand == "watch-list":
        for watch in SESSION.query(WatchList).all():
            print(f"{watch.cve}     {watch.created}")
    elif args.subcommand == "watch-get":
        for watch in SESSION.query(WatchList).all():
            if match := SESSION.get(NVD, cve=watch.cve):
                print(match)
    elif args.subcommand == "watch-add":
        for cve in args.cve:
            if not SESSION.get(WatchList, cve=cve):
                watcher = WatchList(cve=cve)
                SESSION.add(watcher)
        SESSION.commit()
        print(list(SESSION.query(WatchList).all()))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
