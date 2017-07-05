#!/usr/bin/env python
# -*- coding: utf-8 -*-

import math
import argparse
import re
from collections import defaultdict

import git
import enchant

# Because the TemporaryDirectory context manager was added in 3.2
from backports import tempfile

# @@ (source offset, length) (target offset, length) @@ (section header)
RE_HUNK_HEADER = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))?\ @@[ ]?(.*)")

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

d = enchant.Dict("en_US")
context = 3

def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('git_url', type=str, help='URL for secret searching')
    args = parser.parse_args()
    suspicious_commits = find_strings(args.git_url)
    print_commits(suspicious_commits)


def print_commits(commits):
    for commit in commits:
        def cprint(string, col):
            print(col + string + colour.ENDC)

        cprint('commit %s' % commit['commit_sha'], colour.YELLOW)
        print('Author: %s' % commit['author'])
        print('Date:   %s' % commit['date'].strftime('%Y-%m-%d %H:%M:%S') + ' (%s)' % (commit['author_tz_offset']/60/60))
        print
        print('    %s' % commit['short_message'])
        print
        
        for blob in commit['suspicious_blobs']:
            #cprint('index FOO..FOO BAR', colour.BOLD)
            cprint('diff --git a/%s b/%s' % (blob['path'], blob['path']), colour.BOLD)
            cprint('--- a/%s' % blob['path'], colour.BOLD)
            cprint('+++ b/%s' % blob['path'], colour.BOLD)

            hunk = None
            line_no = None

            def print_hunk(hunk):
                if hunk is not None and hunk['highlight_lines']:
                    lines_to_output = set()
                    for offset in hunk['highlight_lines']:
                        start = offset-context
                        end = offset+context+1
                        if start < 0:
                            start = 0
                        if end > len(hunk['lines']):
                            end = len(hunk['lines'])
                        lines_to_output.update(range(start, end))

                    line_list = sorted(list(lines_to_output))

                    index = None
                    lines_removed = lines_added = lines_context = 0
                    for offset in line_list:
                        if hunk['lines'][offset].startswith('-'):
                            lines_removed += 1
                        elif hunk['lines'][offset].startswith('+'):
                            lines_added += 1
                        else:
                            lines_context += 1

                    for offset in line_list:
                        if offset-1 != index:
                            if index:
                                print # Space between hunks
                            index = offset

                            start = hunk['source'] + offset - context
                            if start < 0:
                                start = 0

                            cprint("@@ -%d,%d %d,%d @@" % (
                                start,
                                lines_context + lines_removed,
                                start,
                                lines_context + (lines_added - lines_removed),
                            ), colour.CYAN)
                        else:
                            index += 1

                        if hunk['lines'][offset].strip():
                            print(hunk['lines'][offset])
                    print

            for line in blob['diff'].splitlines():
                header_info = RE_HUNK_HEADER.match(line)
                if header_info:
                    print_hunk(hunk)

                    line_no = 0
                    source, s_len, target, t_len, _ = header_info.groups()
                    hunk = {
                        'source': int(source),
                        'target': int(target),
                        'lines': [],
                        'highlight_lines': set(),
                    }
                    continue

                for string in blob['suspicious_strings']:
                    if string in line:
                        line = line.replace(string, colour.BOLD + colour.RED + string + colour.ENDC)
                        hunk['highlight_lines'].add(line_no)

                hunk['lines'].append(line)
                line_no += 1

            print_hunk(hunk)


def shannon_entropy(data):
    bit = 1.0 / len(data)
    counts = defaultdict(lambda: 0)
    for char in data:
        counts[char] += bit

    entropy = 0
    for _, frequency in counts.items():
        entropy += - frequency * math.log(frequency, 2)

    return entropy


def strings_matching(line, char_set, threshold=15):
    return re.findall('[%s]{%d,}' % (char_set, threshold), line)


def is_probably_language(string, language='en'):
    string = string.replace('/', ' ')

    upper_sentence = re.findall('[A-Z][^A-Z]+', string)
    count = 0
    for word in upper_sentence:
        if d.check(word.strip()):
            count += 1

    if count > len(upper_sentence) / 2:
        return True
    else:
        return False

def find_suspicious_strings(line):
    found = []

    base64_strings = strings_matching(line, BASE64_CHARS)
    for string in base64_strings:
        if shannon_entropy(string) > 4.0 and not is_probably_language(string):
            found.append(string)

    hex_strings = strings_matching(line, HEX_CHARS)
    for string in hex_strings:
        if shannon_entropy(string) > 3 and not is_probably_language(string):
            found.append(string)

    return found


filters = ["node_modules"]
def is_filtered_path(path):
    for string in filters:
        if string in path:
            return True
    return False


class colour:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    YELLOW = '\033[33m'
    FAIL = '\033[31m'
    RED = '\033[41m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CYAN = '\033[36m'


def find_strings(git_url):
    with tempfile.TemporaryDirectory() as checkout_path:
        repo = git.Repo.clone_from(git_url, checkout_path)

        suspicious_commits = []
        seen_commits = set()
        for remote_branch in repo.remotes.origin.fetch():
            branch_name = str(remote_branch).split('/')[1]
            try:
                repo.git.checkout(remote_branch, b=branch_name)
            except:
                pass

            for commit in repo.iter_commits():
                # Skip commits we've already seen on other branches
                if commit.hexsha in seen_commits:
                    continue
                seen_commits.add(commit.hexsha)

                # Skip merge commits
                if len(commit.parents) > 1:
                    continue

                if not commit.parents:
                    # For root commits we diff against the empty tree
                    diff = commit.diff(git.NULL_TREE, create_patch=True)
                else:
                    parent = commit.parents[0]
                    diff = parent.diff(commit, create_patch=True)

                suspicious_blobs = []
                for blob in diff:
                    if is_filtered_path(blob.a_path or blob.b_path):
                        continue

                    printableDiff = blob.diff.decode('utf-8', errors='replace')
                    if printableDiff.startswith('Binary files'):
                        continue

                    lines = blob.diff.decode('utf-8', errors='replace').split('\n')

                    removed_strings = []
                    added_strings = []
                    for line in lines:
                        # Skip submodules
                        if line.startswith('+Subproject commit'):
                            continue

                        if line.startswith('-'):
                            removed_strings.extend(find_suspicious_strings(line[1:]))

                        if line.startswith('+'):
                            added_strings.extend(find_suspicious_strings(line[1:]))

                    # This isn't done with sets as we care about duplicates of
                    # "bad" strings being added to files
                    for string in removed_strings:
                        if string in added_strings:
                            del added_strings[added_strings.index(string)]

                    if len(added_strings) > 0:
                        suspicious_blobs.append({
                            'diff': blob.diff.decode('utf-8', errors='replace'),
                            'path': blob.a_path or blob.b_path,
                            'suspicious_strings': added_strings,
                            'hexes': blob.a_blob or blob.b_blob,
                        })

                if suspicious_blobs:
                    suspicious_commits.append({
                        'date':  commit.authored_datetime,
                        'author_tz_offset': commit.author_tz_offset,
                        'author': '%s <%s>' % (commit.author.name, commit.author.email),
                        'branch': branch_name,
                        'short_message': commit.summary,
                        'commit_sha': commit.hexsha,
                        'suspicious_blobs': suspicious_blobs,
                    })

        return suspicious_commits


if __name__ == '__main__':
    main()
