#!/usr/bin/env python3

import sys, io, os, re
import asyncio, aiodns
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from functools import wraps
import signal
import logging
import tldextract
from ipwhois import IPWhois
from tqdm import tqdm
import argparse
import traceback

MAX_PARALLEL_TASKS=100

DOMAIN_ALIASES = {
    "AWS": [r'amazon', 'awsdns', 'cloudfront', 'ec2'],
    "Microsoft": [r'msft.net', r'microsoft', r'msedge.net', r'hotmail.com', r'outlook.com', r'outlook.cn'],
    "Google": [r'google.com', r'google'],
    "Adobe": [r'adobe'],
    "Fastly": [r'fastly'],
    "IBM/Softlayer": [r'ibm corporation', r'ibm.com', r'softlayer'],
    "Alibaba": [r'aliyun', r'taobao', r'alibaba'],
    "OVH": [r'ovh.net', r'runabove', r'ovh\s'],
    "Gandi": [r'gandi.net', r'gandi'],
    "Rackspace": [r'rackspace', r'Cloud Loadbalancing as a Service-LBaaS'],
    "Iliad": [r'online.net', r'iliad', r'free.fr', r'proxad', r'dedibox'],
    "Cloudflare": [r'cloudflare'],
    "Dyn": [r'dynect.net', r'Dynamic Network Services'],
    "Akamai": [r'akam.net', r'akamai'],
    "UltraDNS": [r'ultradns'],
    "CHINANET": [r'chinanet'],
    "China UNICOM": [r'china unicom'],
    "Digital Ocean": [r'Digital Ocean', r'DigitalOcean'],
    "1and1": [r'1and1', r'1&1', r'Internet AG'],
    "Claranet": [r'typhon', r'claranet', r'clara.net'],
    "Linkbynet": [r'linkbynet'],
    "Hetzner": [r'Hetzner'],
    "Bouygues Tel.": [r'BOUYGUES'],
    "SFR": [r'sfrbusinessteam.fr', r'sfr.com', r'sfr.fr', r'Societe Francaise du Radiotelephone', 'SFR Business', 'SFR GPRS'],
    "Orange": [r'orange-business.com', r'oleane.net', r'OBS Customer', r'francetelecom.com'],
    'Ikoula': [r'ikoula'],
    'Atos': [r'Atos Worldline', 'atos.net'],
    'Jaguar Network': [r'Jaguar Network'],
    'Colt': [r'coltfrance.com', r'colt-telecom.com', r'colt.net', r'COLT Technology Services'],
    'SafeBrands': [r'safebrands.fr', 'mailclub' ],
    'Alter Way': [r'Alter Way Hosting', 'nexen.net'],
    'Joyent': [r'Joyent'],
    'Oxalide': [r'Oxalide'],
    'Peer 1': [r'Peer 1\s'],
    'Integra': [r'Integra'],
    'Linode': [r'linode'],
    'EIG': [r'unifiedlayer', r'websitewelcome', r'bluehost', r'hostgator'],
    'DreamHost': [r'New Dream Network']
}

# Compile the regex ahead of time (case insensitive)
for k, l in DOMAIN_ALIASES.items():
    DOMAIN_ALIASES[k] = [re.compile(i, re.IGNORECASE) for i in l]
 


_detailed_output = False
_debug_mode = False
"""
    Parse command line arguments
"""
def parse_args():
    global _detailed_output, _debug_mode
    parser = argparse.ArgumentParser(description='Collect domain information.')
    parser.add_argument('--detailed', action='store_true',
                        help="provide detailed information")
    parser.add_argument('--debug', action='store_true',
                        help="enable debug mode")
    args = parser.parse_args()
    if args.detailed:
        _detailed_output = True
    if args.debug:
        _debug_mode = True
    return args

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
        try:
            await f
        except:
            logging.warning(traceback.format_exc())

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
                                executor=None):
    if not executor:
        executor = _EXECUTOR
    with (await sem):
        # The semaphore will ensure no more than
        # MAX_PARALLEL_TASKS are scheduled in parallel
        domain = get_registered_domain(entry)

        # Return if unable to parse the domain
        if not domain:
            logging.info ("[!] Could not parse [{}] into a valid domain".format(entry))
            print("{}\tNone\tNone\tNone\tNone".format(entry))
            return

        loop = asyncio.get_event_loop()

        queries = {}
        for record in ('A', 'MX', 'NS'):
            queries[record] = dns_query_safe(domain, record)

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
        whois_info = {}
        a_ip_network_description = None
        if a_ip:
            whois_info = await loop.run_in_executor(_EXECUTOR, ipwhois, a_ip)
            a_ip_network_description = whois_info.get("description", "N/A").split("\n")[0]
            a_ip_network_description = get_alias_for_domain(a_ip_network_description)

        if not _detailed_output:
            print("{entry}\t{domain}\t{ns_host}\t{mx_host}\t{a_ip_network_description}".format(**locals()),
                  flush=True)
        else:
            line = "{entry}\t{domain}\t{ns}\t{mx}\t{net_desc}\t{net_handle}\t" + \
                    "{net_name}\t{net_country}\t{net_cidr}"
            line = line.format(**{
                    "entry": entry,
                    "domain": domain,
                    "ns": ns_host,
                    "mx": mx_host,
                    "net_desc": a_ip_network_description,
                    "net_handle": whois_info.get("handle", "N/A"),
                    "net_name": whois_info.get("name", "N/A"),
                    "net_country": whois_info.get("country", "N/A"),
                    "net_cidr": whois_info.get("cidr", "N/A")
                })
            print(line, flush=True)


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
    Decorator fonction to filter the fields which will be
    looked up by IPWhois._parse_fields() for performance
    reasons. Drastic speed boost.
"""
def filtered_whois(f, field_filter=()):
    @wraps(f)
    def wrapper(*args, **kwargs):
        fields_dict = args[2]
        if len(field_filter) > 0:
            fields_dict = {k:v for (k,v) in fields_dict.items() if k in field_filter}
        return f(args[0], args[1], fields_dict, **kwargs)
    return wrapper
IPWhois._parse_fields = filtered_whois(IPWhois._parse_fields,
                                        ("name", "description", "handle"
                                            "cidr", "country"))

"""
    Returns IPWhois information for a given ip_address.
    Returns a dictionary of name, handle, description, country, cidr
"""
def ipwhois(ip_address):
    try:
        whois = IPWhois(ip_address).lookup()
        whois_info = whois["nets"][0]
        # Special case for JNIC. Use the second network info in that case.
        if whois_info.get("description") == "Japan Network Information Center":
            whois_info = whois["nets"][1]
        return whois_info
        #result = whois["nets"][0].get("description", "N/A")
        #return result.split("\n")[0] # return only first line (if multilines)
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
    Custom ProcessPoolExecutor which sets worker process
    as daemons.
"""
class PbyProcessPoolExecutor(ProcessPoolExecutor):
    def __init__(self, max_workers=None):
        super().__init__(max_workers)

    def _adjust_process_count(self):
        from concurrent.futures.process import _process_worker

        for _ in range(len(self._processes), self._max_workers):
            p = multiprocessing.Process(
                    target=_process_worker,
                    args=(self._call_queue,
                          self._result_queue),
                    daemon=True)
            p.start()
            self._processes[p.pid] = p
_EXECUTOR = PbyProcessPoolExecutor(max_workers=10)

"""
    Cancell all tasks and stop the loop
"""
def stop_loop():
    loop = asyncio.get_event_loop()
    logging.debug("***** Stopping the loop *****")
    if loop.is_running():
        tasks = asyncio.Task.all_tasks(loop)
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
    logging.warning("*** Got Interrupt Signal. ***")
    logging.warning("*** Shutting down the loop (can take a long time). ***")
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
    if _debug_mode:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

def main():
    # Setup logger
    setup_logger()

    # Parse args
    parse_args()

    # Get the main event loop
    loop = asyncio.get_event_loop()

    # Set asyncio debuging
    loop.set_debug(_debug_mode)
    
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