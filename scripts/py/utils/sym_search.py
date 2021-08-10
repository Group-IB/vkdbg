#!/usr/bin/python3

#    This file is part of the vkdbg distribution (https://github.com/Group-IB/vkdbg).
#    Copyright (C) 2021 Timur Chernykh
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
import os
import re
import sys
from pprint import pprint

import requests


def error(msg: str) -> None:
    print(f"[!] {msg}")


def message(msg: str) -> None:
    print(f"[+] {msg}")


def message_continue(msg: str) -> None:
    print(f"\t{msg}")


def _is_key(arg: str) -> bool:
    if len(arg) == 0:
        return False

    if arg[0] == "-":
        return True

    else:
        return False


def _check_key(arg: str, short: str, long: str) -> bool:
    if arg == f"-{short}":
        return True

    if arg == f"--{long}":
        return True

    return False


def _check_key_value(arg: str, short: str, long: str) -> bool:
    if f"-{short}=" in arg:
        return True

    if f"--{long}=" in arg:
        return True

    return False


def _get_key_value(arg: str) -> str:
    key_value = arg.split("=")
    if len(key_value) > 1:
        return key_value[1]
    return ""


class Symbol:
    documented = 0
    defined_macro = 0
    defined_proto = 0
    defined_func = 0
    referenced = 0
    member = 0

    def data(self):
        return {
            "documented": self.documented,
            "macro": self.defined_macro,
            "prototype": self.defined_proto,
            "function": self.defined_func,
            "referenced": self.referenced
        }

    def exists(self):
        return self.documented or self.defined_macro or self.defined_proto or self.defined_func or self.referenced


def get_linux_versions():
    resp = requests.get('https://elixir.bootlin.com/linux/latest/source')
    return re.findall(r"v([\d]*.[\d].*)/source", resp.text)


def chunk(seq, num):
    avg = len(seq) / float(num)
    out = []
    last = 0.0

    while last < len(seq):
        out.append(seq[int(last):int(last + avg)])
        last += avg

    return out


class SearchOptions:
    first_only = False
    verbose = False


def find_occurrence(versions: list, symb: str, search_options: SearchOptions) -> (any, bool):
    all_symbols = []

    for version in versions:

        if search_options.verbose:
            message(f"Checking up version: {version} (https://elixir.bootlin.com/linux/v{version}/A/ident/{symb})")
        else:
            message(f"Checking up version: {version}")

        resp = requests.get(f"https://elixir.bootlin.com/linux/v{version}/A/ident/{symb}")

        sym = Symbol()

        defined_prototypes = re.findall("Defined.* prototype:", resp.text)
        defined_prototypes_n = 0

        defined_member = re.findall("Defined.* member:", resp.text)
        defined_member_n = 0

        defined_macro = re.findall("Defined.* macro:", resp.text)
        defined_macro_n = 0

        defined_func = re.findall("Defined.* function:", resp.text)
        defined_func_n = 0

        referenced = re.findall("Referenced.* files:", resp.text)
        referenced_n = 0

        documented = re.findall("Documented.* files:", resp.text)
        documented_n = 0

        if len(defined_prototypes) > 0:
            defined_prototypes = defined_prototypes[0]
            defined_prototypes_n = int(re.search(r"\d+", defined_prototypes)[0])

        if len(defined_member) > 0:
            defined_member = defined_member[0]
            defined_member_n = int(re.search(r"\d+", defined_member)[0])

        if len(defined_macro) > 0:
            defined_macro = defined_macro[0]
            defined_macro_n = int(re.search(r"\d+", defined_macro)[0])

        if len(defined_func) > 0:
            defined_func = defined_func[0]
            defined_func_n = int(re.search(r"\d+", defined_func)[0])

        if len(referenced) > 0:
            referenced = referenced[0]
            referenced_n = int(re.search(r"\d+", referenced)[0])

        if len(documented) > 0:
            documented = documented[0]
            documented_n = int(re.search(r"\d+", documented)[0])

        if defined_prototypes_n:
            sym.defined_proto = int(defined_prototypes_n)

        if defined_member_n:
            sym.member = int(defined_member_n)

        if defined_macro_n:
            sym.defined_macro = int(defined_macro_n)

        if defined_func_n:
            sym.defined_func = int(defined_func_n)

        if referenced_n:
            sym.referenced = int(referenced_n)

        if documented_n:
            sym.documented = int(documented_n)

        if sym.exists() and search_options.first_only:
            return sym, True

        all_symbols.append(sym)

    return all_symbols, False


def help_usage():
    message(f"Search symbol via elixir.bootin")
    message_continue("vkdbg search symbol <symbol> [flags]")
    message_continue("Available flags:")
    message_continue("\t-h  | --help       \t- show this message")
    message_continue("\t-fo | --first-only \t- search first symbol occurrence")
    message_continue("\t-mo | --major-only \t- search in major versions only")
    message_continue("\t-up | --up-to      \t- search in version greater than")
    message_continue("\t-v  | --verbose    \t- verbose output")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        help_usage()
        exit(1)

    all_versions = get_linux_versions()
    all_versions.reverse()

    major_only_flag = False
    up_to_flag = False
    up_to_value = ""

    symbol = ""
    search_options = SearchOptions()

    for arg in sys.argv[1::]:
        if _check_key(arg, "h", "help"):
            help_usage()
            exit(0)

        if _check_key(arg, "fo", "first-only"):
            search_options.first_only = True
            continue

        if _check_key(arg, "mo", "major-only"):
            major_only_flag = True
            continue

        if _check_key(arg, "v", "verbose"):
            search_options.verbose = True
            continue

        if _check_key_value(arg, "up", "up-to"):
            up_to_flag = True
            up_to_value = _get_key_value(arg)
            continue

        if not _is_key(arg):
            symbol = arg
            continue

    if up_to_flag:
        i = 0
        for version in all_versions:
            if version.startswith(up_to_value):
                message(f"Slice up to version {version}")
                all_versions = all_versions[i::]
                break

            i += 1

    if major_only_flag:
        major_versions = []
        for version in all_versions:
            version_split = version.split(".")
            if len(version_split) > 2 and version_split[2] != '0':
                continue
            major_versions.append(version)
            all_versions = major_versions

    if not symbol:
        help_usage()
        exit(1)

    sym, found = find_occurrence(all_versions, symbol, search_options)

    if found:
        if search_options.first_only:
            pprint(sym.data())
            exit(0)
        for sym_found in sym:
            pprint(sym_found.data())
            exit(0)
    else:
        error("Symbol not found :(")
