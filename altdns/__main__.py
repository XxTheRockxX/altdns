#!/usr/bin/env python3
# Developed and Released at BSides Canberra by @infosec_au and @nnwakelam
# Updated 3/1/2023 @Th3R0ck - Duane Johnson

import argparse
import threading
try:
   import Queue as queue
except ImportError:
   import queue as queue

import tldextract, sys
#from tldextract.tldextract import LOG
import logging

logging.basicConfig(level=logging.CRITICAL)

terminate_threads = False
output_bytes_count = 0
output_bytes_limit = 0
lock = threading.Lock()

def read_file_linebyline(filename):
    with open(filename, 'r') as f:
        for line in f:
            yield line.rstrip()

def get_alteration_words(wordlist_fname):

    with open(wordlist_fname, "r") as f:
        wordlist = list()
        for line in f.readlines():
            wordlist.append(line.rstrip())
        return wordlist

def permutate_number_suffix_domains(current_sub, ext):
    subdomain_permutations = {}
    for word in range(0, 10):
        for index, value in enumerate(current_sub):
            # add word-NUM
            original_sub = current_sub[index]
            current_sub[index] = current_sub[index] + "-" + str(word)
            # join the list to make into actual subdomain (aa.bb.cc)
            actual_sub = ".".join(current_sub)
            # save full URL as line in file
            full_url = "{0}.{1}.{2}".format(actual_sub, ext.domain, ext.suffix)
            #write_domain(args, wp, full_url)
            subdomain_permutations[full_url] = 0
            current_sub[index] = original_sub

            # add wordNUM
            original_sub = current_sub[index]
            current_sub[index] = current_sub[index] + str(word)
            # join the list to make into actual subdomain (aa.bb.cc)
            actual_sub = ".".join(current_sub)
            # save full URL as line in file
            full_url = "{0}.{1}.{2}".format(actual_sub, ext.domain, ext.suffix)
            subdomain_permutations[full_url] = 0
            #write_domain(args, wp, full_url)
            current_sub[index] = original_sub

    return subdomain_permutations

def permutate_dashed_subdomains(current_sub, word, ext):
    subdomain_permutations = {}
    for index, value in enumerate(current_sub):
        original_sub = current_sub[index]
        current_sub[index] = current_sub[
                                 index] + "-" + word.strip()
        # join the list to make into actual subdomain (aa.bb.cc)
        actual_sub = ".".join(current_sub)
        # save full URL as line in file
        full_url = "{0}.{1}.{2}".format(
            actual_sub, ext.domain, ext.suffix)
        if len(current_sub[0]) > 0 and actual_sub[:1] != "-":
            subdomain_permutations[full_url] = 0
            #write_domain(args, wp, full_url)
        current_sub[index] = original_sub
        # second dash alteration
        current_sub[index] = word.strip() + "-" + \
                             current_sub[index]
        actual_sub = ".".join(current_sub)
        # save second full URL as line in file
        full_url = "{0}.{1}.{2}".format(
            actual_sub, ext.domain, ext.suffix)
        if actual_sub[-1:] != "-":
            subdomain_permutations[full_url] = 0#write_domain(args, wp, full_url)
        current_sub[index] = original_sub

    return subdomain_permutations

def permutate_index_subdomain(current_sub, word, ext):
    subdomain_permutations = {}
    for index in range(0, len(current_sub)):
        current_sub.insert(index, word.strip())
        # join the list to make into actual subdomain (aa.bb.cc)
        actual_sub = ".".join(current_sub)
        # save full URL as line in file
        full_url = "{0}.{1}.{2}".format(
            actual_sub, ext.domain, ext.suffix)
        if actual_sub[-1:] != ".":
            subdomain_permutations[full_url] = 0
            #pass  # write_domain(args, wp, full_url)
        current_sub.pop(index)
    current_sub.append(word.strip())
    actual_sub = ".".join(current_sub)
    full_url = "{0}.{1}.{2}".format(
        actual_sub, ext.domain, ext.suffix)
    if len(current_sub[0]) > 0:
        subdomain_permutations[full_url] = 0  # write_domain(args, wp, full_url)
    current_sub.pop()

    return subdomain_permutations

def permutation_prefix_suffix_subdomain(current_sub, word, ext):
    subdomain_permutations = {}
    for index, value in enumerate(current_sub):
        original_sub = current_sub[index]
        current_sub[index] = current_sub[index] + word.strip()
        # join the list to make into actual subdomain (aa.bb.cc)
        actual_sub = ".".join(current_sub)
        # save full URL as line in file
        full_url = "{0}.{1}.{2}".format(
            actual_sub, ext.domain, ext.suffix)
        subdomain_permutations[full_url] = 0 #write_domain(args, wp, full_url)
        current_sub[index] = original_sub
        # second dash alteration
        current_sub[index] = word.strip() + current_sub[index]
        actual_sub = ".".join(current_sub)
        # save second full URL as line in file
        full_url = "{0}.{1}.{2}".format(
            actual_sub, ext.domain, ext.suffix)
        subdomain_permutations[full_url] = 0 #write_domain(args, wp, full_url)
        current_sub[index] = original_sub
    return subdomain_permutations

def worker(q, alteration_words):
    global terminate_threads, output_bytes_count, output_bytes_limit
    while True:
        subdomain = q.get()
        if subdomain is None:
            # This is the signal to exit
            q.task_done()
            break
        if terminate_threads is True:
            q.task_done()
            break
        if output_bytes_count > output_bytes_limit:
            terminate_threads=True
            q.task_done()
            break
        subdomain = subdomain.rstrip()
        ext = tldextract.extract(subdomain)
        current_sub = ext.subdomain.split(".")
        for item in permutate_number_suffix_domains(current_sub=current_sub, ext=ext):
            print(item)
            output_bytes_count += len(item) + 1
        for word in alteration_words:
            for item in permutate_index_subdomain(current_sub=current_sub, word=word, ext=ext):
                print(item)
                output_bytes_count += len(item) + 1
            for item in permutate_dashed_subdomains(current_sub=current_sub, word=word, ext=ext):
                print(item)
                output_bytes_count += len(item) + 1
            for item in permutation_prefix_suffix_subdomain(current_sub=current_sub, word=word, ext=ext):
                print(item)
                output_bytes_count += len(item) + 1

        q.task_done()


def main(args):
    try:
        alteration_words = get_alteration_words(args.wordlist)
        q = queue.Queue()

        # Start the worker threads
        threads = []
        for i in range(int(args.threads)):
            t = threading.Thread(target=worker, args=(q, alteration_words))
            t.start()
            threads.append(t)

        # Read lines from the input file and add them to the queue
        for line in read_file_linebyline(args.input):
            q.put(line.rstrip())

            # Add sentinel values to the queue
        for _ in range(int(args.threads)):
            q.put(None)

        # Wait for all work to be done
        #q.join()

        # Wait for all threads to finish
        for t in threads:
            t.join()
        #generate_all_permutations(args, alteration_words)

    except BrokenPipeError:
        sys.stderr.close()

def size_to_bytes(size):
    unit = size[-1].upper()
    value = float(size[:-1])

    if unit == 'G':
        return int(value * 1024**3)
    elif unit == 'M':
        return int(value * 1024**2)
    else:
        raise ValueError('Invalid size unit. Use G for gigabytes or M for megabytes.')

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input",
                        help="List of subdomains input", #required=True,
                        default="/opt/bb/ford.com.subdomains")
    parser.add_argument("-w", "--wordlist",
                        help="List of words to alter the subdomains with",
                        required=False, default="/opt/wordlists/permwords.txt")
    parser.add_argument("-e", "--ignore-existing",
                        help="Ignore existing domains in file",
                        action="store_true")

    parser.add_argument("-t", "--threads",
                    help="Amount of threads to run simultaneously",
                    required=False, default="60")

    parser.add_argument("-l", "--limit",
                        help="Limit the number of output bytes (e.g., 1G or 500M)",
                        required=False, default="1G")  # New argument to limit the number of output bytes

    return parser.parse_args()


if __name__ == "__main__":
    try:
        args = arg_parser()
        output_bytes_limit = size_to_bytes(args.limit)
        main(args)
    except KeyboardInterrupt:
        print("Interrupted by user. Exiting...")
        terminate_threads=True
        sys.exit(1)
