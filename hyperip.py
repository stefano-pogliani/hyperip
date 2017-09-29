import argparse
import logging
import re

from time import sleep

import requests


RE_LOGIN_TOKEN = re.compile('getObj\("Frm_Logintoken"\).value = "([0-9]+)";')
RE_SESSION_TOKEN = re.compile('var session_token = "(.*)";')
RE_WAN_IP = re.compile('getObj\("TextIPAddress0"\).value="(.*)/.*";')


def extractIp(info):
    """Extract the IP address from the returned page.

    Look for getObj("TextIPAddress0").value="(.*)/.*";
    """
    match = RE_WAN_IP.search(info)
    assert match, 'Could not extract the WAN IP Address'
    return match.group(1)


def extractSessionToken(info):
    """The session token is needed to log out"""
    match = RE_SESSION_TOKEN.search(info)
    assert match, 'Could not find session token'
    return match.group(1)


def getInfo(router):
    """Extract the WAN information from the details page.

    GET /getpage.gch?pid=1002&nextpage=IPv46_status_wan2_if_t.gch
    """
    info = requests.get(router + 'getpage.gch', params={
        'pid': 1002,
        'nextpage': 'IPv46_status_wan2_if_t.gch'
    })
    assert info.ok, 'Failed to get stats'
    return info.text


def getLoginToken(router):
    """HyperOptic routers issuse a loging token.

    It is a simple incrementing integer and easly found.
    This is just security though pain ...
    """
    index = requests.get(router)
    assert index.ok, 'Failed to GET index page'
    match = RE_LOGIN_TOKEN.search(index.text)
    assert match, 'Cannot find login token'
    return match.group(1)


def doLogin(router, username, password, loginToken):
    """Perofrm the login action with the given token.

    The router allows one session at a time (by IP?) with no
    cookies/tokens/basicauth.
    Once the login succeeds we get access to the router knowing the URLs
    """
    logging.info('Attempting login with token: %s', loginToken)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'frashnum': '',
        'action': 'login',
        'Frm_Logintoken': loginToken,
        'Username': username,
        'Password': password
    }
    login = requests.post(
        router, allow_redirects=False,
        data=data, headers=headers
    )
    assert login.status_code == 302, 'Failed to login'


def doLogout(router, session):
    """Logs out of the router."""
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'logout': 1,
        '_SESSION_TOKEN': session
    }
    logout = requests.post(
        router, allow_redirects=False,
        data=data, headers=headers
    )
    assert logout.status_code == 302, 'Failed to log out'


def getStats(router, username, password):
    """Logic implementing the IP exraction process.

    1. Find the current login token.
    2. Login to the router.
    3. Get the stats page.
    4. Log out.
    """
    logging.info('Logging into the router ...')
    loginToken = getLoginToken(router)
    sleep(1)
    doLogin(router, username, password, loginToken)
    sleep(1)
    logging.info('Login success!')

    logging.info('Fetching info ...')
    info = getInfo(router)
    ip = extractIp(info)

    logging.info('Logging out ...')
    session = extractSessionToken(info)
    doLogout(router, session)
    logging.info('Done!')

    return {
        'ip': ip,
        'session': session
    }


def main():
    parser = argparse.ArgumentParser(
        description='Find the PublicIP of an HyperOptic router'
    )
    parser.add_argument(
        'router', type=str, default='http://192.168.1.1/',
        help='The URL of the router to fetch the IP from'
    )
    parser.add_argument(
        '--username', type=str, default='admin',
        help='The username to login as'
    )
    parser.add_argument(
        '--password', type=str, help='The password to login with'
    )
    options = parser.parse_args()
    logging.basicConfig(level=logging.INFO)

    stats = getStats(options.router, options.username, options.password)
    print(u'Your IP Adderss is: {0}'.format(stats['ip']))

if __name__ == '__main__':
    main()
