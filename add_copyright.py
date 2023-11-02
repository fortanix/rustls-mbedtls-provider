#!/bin/env python3
import os

copyright_notice = """/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"""

def add_copyright_to_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    if not content.startswith(copyright_notice):
        with open(file_path, 'w') as file:
            file.write(copyright_notice + content)
            print("Added copyright header to", file_path)

def process_files_in_directory(directory):
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".rs"):
                file_path = os.path.join(root, filename)
                add_copyright_to_file(file_path)

if __name__ == "__main__":
    current_directory = os.getcwd()
    process_files_in_directory(current_directory)
