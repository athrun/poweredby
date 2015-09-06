# *"Powered-by"* finder

This script will crawl a list of internet domains and report which providers are powering the domain.

The script will report the providers used for:

- DNS Services
- Network Operator (can be the hosting provider but also the CDN provider)
- Email services

## Installation

This tool requires Python 3.5 or later.
Use `pip install -r requirements.txt` to install the required dependencies.

## Usage information

## Input format

This tool is expecting an UTF-8 file listing the Internet properties you want to crawl, with one item per line.

Here's a sample valid input file:

    http://www.netflix.com
    http://docs.google.com
    www.algolia.com
    amazon.com

## Output format

The tool will produce on the standard output a Tab-separated listing of this nature:

    <Item>    <Root Domain>    <DNS Provider>    <Hosting Provider>    <Email Provider>

## Sample usage

Given the sample input format presented earlier:

    $ ./pbd.py < input_file > output_file.csv
    100%|█████████████████████████████████████████████| 4/4 [00:06<00:00,  0.60 it/s]
    2015-09-06 21:21:30,415 root         INFO     Completed. 4 entries have been processed

    $ cat output_file.csv
    http://www.netflix.com    netflix.com    UltraDNS    AWS    Google
    http://docs.google.com    google.com    Google    Google    Google
    www.algolia.com algolia.com    Cloudflare    Cloudflare    Google
    amazon.fr    amazon.fr    UltraDNS    AWS    AWS
