#!/usr/bin/env python
# -*- coding: utf-8 -*-

import shutil
import math
import datetime
import argparse
import tempfile
import os
import json
import stat
from git import Repo

def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument('git_url', type=str, help='URL for secret searching')
    args = parser.parse_args()
    output = find_strings(args.git_url)
    project_path = output["project_path"]
    shutil.rmtree(project_path, onerror=del_rw)

    for diff in output["entropicDiffs"]:
        if args.output_json:
            print(json.dumps(output, sort_keys=True, indent=4))
        else:
            print(bcolors.OKGREEN + "Date: " + diff['date'] + bcolors.ENDC)
            print(bcolors.OKGREEN + "Branch: " + diff['branch'] + bcolors.ENDC)
            print(bcolors.OKGREEN + ("Path: %s" % diff['path']) + bcolors.ENDC)
            print(bcolors.OKGREEN + "Commit: " + diff['commit_sha'] + bcolors.ENDC)
            print(bcolors.OKGREEN + "Message: " + diff['commit'] + bcolors.ENDC)
            
            highlightedDiff = diff['diff']
            for string in diff['stringsFound']:
                highlightedDiff = highlightedDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
            print(highlightedDiff)


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)

def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings


def find_suspicious_strings(line):
    stringsFound = []
    for word in line.split():
        base64_strings = get_strings_of_set(word, BASE64_CHARS)
        hex_strings = get_strings_of_set(word, HEX_CHARS)
        for string in base64_strings:
            b64Entropy = shannon_entropy(string, BASE64_CHARS)
            if b64Entropy > 4.5:
                stringsFound.append(string)
        for string in hex_strings:
            hexEntropy = shannon_entropy(string, HEX_CHARS)
            if hexEntropy > 3:
                stringsFound.append(string)
    return stringsFound


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def find_strings(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    output = {
        'entropicDiffs': []
    }
    repo = Repo(project_path)

    seen_commits = set()

    for remote_branch in repo.remotes.origin.fetch():
        branch_name = str(remote_branch).split('/')[1]
        try:
            repo.git.checkout(remote_branch, b=branch_name)
        except:
            pass

        for commit in repo.iter_commits():
            # Skip this for the root commit
            if not commit.parents:
                continue

            # Skip commits we've already seen on other branches
            if commit.hexsha in seen_commits:
                continue
            seen_commits.add(commit.hexsha)

            # Skip merge commits
            if len(commit.parents) > 1:
                continue

            parent = commit.parents[0]
            diff = commit.diff(parent, create_patch=True)
            for blob in diff:
                printableDiff = blob.diff.decode('utf-8', errors='replace')
                if printableDiff.startswith('Binary files'):
                    continue

                lines = blob.diff.decode('utf-8', errors='replace').split('\n')

                removed_strings = set()
                added_strings = set()
                for line in lines:
                    # Skip submodules
                    if line.startswith('+Subproject commit'):
                        continue

                    if line.startswith('-'):
                        removed_strings.update(find_suspicious_strings(line))

                    if line.startswith('+'):
                        added_strings.update(find_suspicious_strings(line))

                stringsFound = list(added_strings - removed_strings)
                if len(stringsFound) > 0:
                    commit_time = datetime.datetime.fromtimestamp(commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
                    
                    output['entropicDiffs'].append({
                        'date':  commit_time,
                        'branch': branch_name,
                        'commit': commit.message,
                        'commit_sha': commit.hexsha,
                        'diff': blob.diff.decode('utf-8', errors='replace'),
                        'path': blob.a_path or blob.b_path,
                        'stringsFound': stringsFound,
                    })


    output['project_path'] = project_path
    return output


if __name__ == '__main__':
    main()
