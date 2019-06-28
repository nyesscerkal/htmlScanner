import argparse
import validators
import requests
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

ip = '192.168.1.1'
report = ''

parser = argparse.ArgumentParser(description='HTML Vulnerability Analyzer Version 1.0')
parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyze")
parser.add_argument('--config', help='Path to configuration file')
parser.add_argument('-o', '--output', help='Filename destination for report')
args = parser.parse_args()

url = args.url
output = args.output

config = {'forms': True, 'comments': True, 'passwords': True}

if args.config:
    print('Using config file: ' + args.config)
    config_file = open(args.config, 'r')
    config_f = yaml.load(config_file, Loader=yaml.FullLoader)
    if config_f:
        config = {**config, **config_f}

if validators.url(url):
    result_html = requests.get(url).text
    parsed_html = BeautifulSoup(result_html, 'html.parser')

    forms = parsed_html.find_all('form')
    comments = parsed_html.find_all(string=lambda text: isinstance(text, Comment))
    passwords = parsed_html.find_all('input', {'name': 'password'})

    if config['forms']:
        for form in forms:
            if form.get('action').find('https') < 0 and urlparse(url).scheme != 'https':
                report += "Form Issue: \tInsecure form action " + form.get('action') + " in document found\n"

    if config['comments']:
        for comment in comments:
            if comment.find('key:') > -1:
                report += "Comment Issue: \tKey is found in the HTML comments\n"

    if config['passwords']:
        for password in passwords:
            if password.get('type') != 'password':
                report += "Input Issue: \tPlaintext password input found\n"

else:
    print('Invalid URL. Please include full URL including scheme.')

if report == '':
    report += "HTML document is secure"
else:
    header = "Vulnerability Report for " + str(url) + "\n"
    report = header + report

if output:
    out = open(output, 'w')
    out.write(report)
    out.close()
    print("Vulnerability Report saved to " + output)


#result = validators.ipv4(ip)