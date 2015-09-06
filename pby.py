#!/usr/bin/env python3

import sys, io, os, re
import asyncio, aiodns
from concurrent.futures import ProcessPoolExecutor
import signal
import logging
import tldextract
from ipwhois import IPWhois
from tqdm import tqdm

MAX_PARALLEL_TASKS=100

DOMAIN_ALIASES = {
    "AWS": [r'amazon', 'awsdns', 'cloudfront.net'],
    "Microsoft": [r'msft.net', r'microsoft', r'msedge.net', r'hotmail.com', r'outlook.com', r'outlook.cn'],
    "Google": [r'google.com', r'google'],
    "Adobe": [r'adobe'],
    "Fastly": [r'fastly'],
    "IBM/Softlayer": [r'ibm corporation', r'ibm.com', r'softlayer'],
    "Alibaba": [r'aliyun', r'taobao', r'alibaba'],
    "OVH": [r'ovh.net', r'ovh hosting', r'OVH SAS'],
    "Illiad": [r'online.net', r'illiad', r'free.fr', r'proxad'],
    "Cloudflare": [r'cloudflare'],
    "Dyn": [r'dynect.net', r'Dynamic Network Services'],
    "Akamai": [r'akam.net', r'akamai'],
    "UltraDNS": [r'ultradns'],
    "CHINANET": [r'chinanet'],
    "China UNICOM": [r'china unicom'],
    "Digital Ocean": [r'Digital Ocean']
}

# Compile the regex ahead of time (case insensitive)
for k, l in DOMAIN_ALIASES.items():
    DOMAIN_ALIASES[k] = [re.compile(i, re.IGNORECASE) for i in l]
 
_EXECUTOR = ProcessPoolExecutor(max_workers=10)

""" Stream from stdin
    'rt' mode = unicode text, 'rb' = binary stream
    'rt' mode is line buffered, 'rb' use a smart buffer
"""
def process_stdin(handler, mode="rt"):
    try:
        with io.open(sys.stdin.fileno(), mode) as sys.stdin:
            # Schedule all tasks to run on the event loop
            tasks = [asyncio.ensure_future(handler(line.strip())) for line in sys.stdin]

            # Schedule a coroutine to track the progress
            asyncio.ensure_future(wait_with_progress(tasks))

            # Schedule a coroutine to run once all tasks have completed
            asyncio.ensure_future(asyncio.wait(tasks)).add_done_callback(tasks_completed)
    except Exception as e:
        logging.exception("Error while reading stdin: {}".format(e))

"""
    Callback after all processing is completed.
"""
def tasks_completed(future):
    if not future.cancelled():
        if not future.exception():
            done, pending = future.result()
            logging.info("Completed. {} entries have been processed".format(len(done)))
        else:
            logging.exception(future.exception())
    else:
        logging.warning("Processing has been cancelled.")

"""
    Stop the loop once all coroutines are done.
"""
def check_tasks_status(loop):
    tasks = asyncio.Task.all_tasks(loop=loop)

    if len(tasks) > 0:
        # Reschedule coroutine
        loop.call_later(1, check_tasks_status, loop)
    else:
        # No tasks/coroutines left!
        logging.debug("** All tasks have completed. Stopping loop. **")
        loop.call_soon(stop_loop)

"""
    Asynchronous progress bar
"""
async def wait_with_progress(coros):
    for f in tqdm(asyncio.as_completed(coros), total=len(coros), leave=True):
        await f

"""
    Asynchronous DNS resolver (safe)
    Exception are catched and won't bubble up
"""
async def dns_query_safe(hostname, record_type, resolver=aiodns.DNSResolver()):
    try:
        return await resolver.query(hostname, record_type)
    except aiodns.error.DNSError:
        return None

"""
    Asynchronous processing of a line of text (entry).
    Max number of parallel processing is bound by a semaphore (sem).
"""
async def process_entry(entry, sem=asyncio.Semaphore(MAX_PARALLEL_TASKS),
                                executor=_EXECUTOR):

    with (await sem):
        # The semaphore will ensure no more than
        # MAX_PARALLEL_TASKS are scheduled in parallel
        domain = get_registered_domain(entry)

        # Return if unable to parse the domain
        if not domain:
            logging.info ("[!] Could not parse [{}] into a valid domain".format(entry))
            print("{}\tN/A\tN/A\tN/A\tN/A".format(entry))
            return

        loop = asyncio.get_event_loop()

        queries = {}
        for record in ('A', 'MX', 'SOA', 'NS'):
            queries[record] = dns_query_safe(domain, record)
        
        # Dealing with SOA record
        #print("SOA for {}".format(domain))
        #soa = await queries["SOA"]
        #soa_host = soa.nsname

        # Perform DNS queries in parallel
        ns, a, mx = await asyncio.gather(queries["NS"], queries["A"], queries["MX"],
                                                return_exceptions=False)

        ns_host = None
        if ns and len(ns) > 0:
            ns_host = get_alias_for_domain(get_registered_domain(ns[0].host))

        a_ip = None
        if a and len(a) > 0:
            a_ip = a[0].host

        mx_host = None
        if mx and len(mx) > 0:
            mx_host = get_alias_for_domain(get_registered_domain(mx[0].host))

        # Ideally loop.run_in_executor(...) could be scheduled as a Task on the event
        # loop (ex: with loop.create_task(...)). But as of py3.5rc2, it's not
        # added to the task list (asyncio.Task.all_tasks) making it impossible
        # to know when all Tasks are completed.
        a_ip_network = None
        if a_ip:
            #pass
            #await loop.run_in_executor(executor, small_test, domain)
            a_ip_network = await loop.run_in_executor(_EXECUTOR, ipwhois, a_ip)
            a_ip_network = get_alias_for_domain(a_ip_network)
            #a_ip_network = ipwhois(a_ip)

        print("{entry}\t{domain}\t{ns_host}\t{a_ip_network}\t{mx_host}".format(**locals()))

"""
    Get the registered domain from an URL or an hostname.
"""
def get_registered_domain(url):
    # Use pre-built suffix list only.
    # See https://github.com/john-kurkowski/tldextract
    # for more details on the suffix list if updates are required.
    offline_extract = tldextract.TLDExtract(suffix_list_url=False)
    domain = offline_extract(url).registered_domain
    if len(domain):
        return domain
    else:
        return None

"""
    Returns IPWhois information for a given ip_address.
"""
def ipwhois(ip_address):
    try:
        whois = IPWhois(ip_address).lookup()
        result = whois["nets"][0].get("description", "N/A")
        return result.split("\n")[0] # return only first line (if multilines)
    except:
        return ip_address

"""
    Return the network owner's alias
    (ie: Amazon, Google, etc.)
"""
def get_alias_for_domain(domain_information):
    if domain_information:
        for alias, l in DOMAIN_ALIASES.items():
            for i in l:
                if i.search(domain_information): # Got a match!
                    return alias

    return domain_information

"""
    Cancell all tasks and stop the loop
"""
def stop_loop(loop=asyncio.get_event_loop()):
    logging.debug("***** Stopping the loop *****")
    if loop.is_running():
        tasks = asyncio.Task.all_tasks(loop=loop)
        if len(tasks) > 0:
            # Cancel all tasks
            logging.debug("Cancelling all pending coroutines...")
            for f in tasks:
                f.cancel()
            # Shutdown executor and wait for it
            logging.debug("Waiting for background processes to complete...")
            _EXECUTOR.shutdown(wait=True)
            # Reschedule the function on next tick
            loop.call_soon(stop_loop)

        # If no tasks left, close the loop
        loop.stop()
    else:
        logging.warning("***** Loop is not running! *****")

"""
    SIGINT or SIGTERM interrupt handler
"""
def on_interrupt_signal():
    logging.warning("*** Got Interrupt Signal ***")
    stop_loop()

"""
    Initialize the logging system
"""
def setup_logger():
    logger = logging.getLogger()
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def main():
    # Setup logger
    setup_logger()

    # Get the main event loop
    loop = asyncio.get_event_loop()

    # Set asyncio debuging
    loop.set_debug(False)
    
    # Schedule main entry point
    loop.call_soon(process_stdin, process_entry)

    # Schedule loop monitoring callback
    loop.call_later(1, check_tasks_status, loop)

    # Handle SIGTERM and SIGINT
    for signame in ('SIGINT', 'SIGTERM'):
        loop.add_signal_handler(getattr(signal, signame),
                                on_interrupt_signal)

    # Run the event loop
    try:
        loop.run_forever()
    except:
        logging.exception("*** Got exception in loop.run_forever() ***")
        stop_loop()
    finally:
        loop.close()

if __name__ == '__main__':
    main()