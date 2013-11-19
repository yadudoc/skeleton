import urllib2, sys
from fabric import colors

urls = [ 'https://core.test.expa.com', 'https://gis.test.expa.com', 'https://www.test.expa.com', 'https://test.expa.com', 'http://blog.test.expa.com']
url_response = dict.fromkeys(urls)
for url in urls:
    try:
        response = urllib2.urlopen(url)
        url_response[url] = response.code
        print url + ": " + colors.green(str(response.code))
    except urllib2.HTTPError, error:
        print url + ": " + colors.red(error.code)
    except urllib2.URLError, error:
        print url + ": " + colors.red(error.args)

try:
    type(error)
    sys.exit(1)
except NameError:
    if range(401, 600) in url_response.values():
        sys.exit(1)
