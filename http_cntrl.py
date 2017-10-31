""" HTTP handler for running scripts at the server 
"""

import argparse
import os
import SocketServer
import subprocess
import SimpleHTTPServer

""" Configure SimpleHTTPServer handler
Returns: SimpleHTTPRequestHandler with basic authentification 
"""
def make_handler(key, routing):
    class AuthHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
        # Static members
        key_ = key
        routing_ = routing

        def do_GET(self):
            if self.headers.getheader('Authorization') == 'Basic %s' % self.key_: # Authorized
                alias = self.path[1:]  # remove leading '/'
                script = self.routing_.get(alias, None) 
                if script is None or not os.path.isfile(script): # routing and target script are exist 
                    self.send_response(404)
                else:
                    script_realpath = os.path.realpath(script)
                    print "%s: Run %s" % (self.client_address[0], script_realpath)
                    # Run the command
                    subprocess.check_call(
                        ["/bin/sh", script_realpath], stdout=self.wfile)
            else:  # Not authorized
                self.send_response(401)

    return AuthHandler

def run(root, port, routing, key):
    """ Run server 
    root: root directory for scripts
    port: server port
    routing: routing dictionary
    key: 'username:password' encoded by base64
    """
    os.chdir(root) # Run from the 
    httpd = SocketServer.TCPServer(("", port), make_handler(key, routing))
    print "serving %s at port: %d\nCtrl+C to Quit" % (root, port)
    httpd.serve_forever()


def build_routing(routes):
    """ Parse the list of strings that represent routing
    Routes is a list of strings. Each string should have a form "alias1:script1"
    """
    result = {}
    for route in routes:
        route_splitted = route.split(':')
        if len(route_splitted) != 2:
            raise Exception(
                'Wrong route format for "%s". Should be in form path:script_to_run' % route)
        key, value = route_splitted
        result[key] = value

    return result


def main():
    """ Parse command line arguments and run the server """
    parser = argparse.ArgumentParser(description="A simple backdoor server")
    parser.add_argument('--root', "-r", default=".",
                        help="Root directory to serve scripts from")
    parser.add_argument('--port', "-p", default=8000,
                        type=int, help="port to run the server on")

    parser.add_argument('--route', action='append',
                        help="route mapping in form of path:script_to_run, e.g. restart:restart.sh")
    parser.add_argument('--key', "-k", required=True,
                        help="base64 encoded key. You can generate it in python: import base64;base64.b64encode('your_username:your_password')")

    args = parser.parse_args()

    if os.path.isdir(args.root):
        run(args.root, args.port, build_routing(args.route), args.key)
    else:
        print "not a valid directory %s" % args.root


if __name__ == '__main__':
    main()
