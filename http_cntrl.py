#!/usr/bin/env python

""" HTTP handler for running scripts at the server 
"""

import argparse
import os
import crypt
import SocketServer
import subprocess
import SimpleHTTPServer

""" Configure SimpleHTTPServer handler
Returns: SimpleHTTPRequestHandler with basic authentification 
"""
def make_handler(key, salt, routing):
    class AuthHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
        # Static members
        key_ = key
        routing_ = routing
        salt_ = salt

        def do_GET(self):
            auth_header = self.headers.getheader('Authorization')
            is_auth = True
            if auth_header and auth_header.startswith('Basic') and len(auth_header.split()) == 2:
                _, b64_user_pass = auth_header.split()

                if crypt.crypt(b64_user_pass, self.salt_) == self.key_: # Authorized
                    is_auth = True
                    alias = self.path[1:]  # remove leading '/'
                    script = self.routing_.get(alias, None) 
                    if script is None or not os.path.isfile(script): # routing and target script are exist 
                        self.send_response(404)
                    else:
                        script_realpath = os.path.realpath(script)
                        print("%s: Run %s" % (self.client_address[0], script_realpath))
                        # Run the command
                        subprocess.check_call(
                            ["/bin/sh", script_realpath], stdout=self.wfile)
            
            if not is_auth: #Not authorized
                self.send_response(401)
            
    return AuthHandler

def run(root, port, routing, key, salt):
    """ Run server 
    root: root directory for scripts
    port: server port
    routing: routing dictionary
    key: 'username:password' encoded by base64
    """
    root_realpath = os.path.realpath(root)
    os.chdir(root_realpath) # Run from the 
    httpd = SocketServer.TCPServer(("", port), make_handler(key, salt, routing))
    print "serving %s at port: %d\nCtrl+C to Quit" % (root_realpath, port)
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
    parser = argparse.ArgumentParser(description="A simple backdoor HTTP server")
    parser.add_argument('--root', "-r", default=".",
                        help="Root directory to serve scripts from")
    parser.add_argument('--port', "-p", default=8000,
                        type=int, help="port to run the server on")

    parser.add_argument('--route', action='append',
                        help="route mapping in form of path:script_to_run, e.g. restart:restart.sh")
    parser.add_argument('--salt', "-s", default='criteo',
                        help="Crypt's salt parameter for crypt function. See --key parameter")
    parser.add_argument('--key', "-k", required=True,
                        help="base64 encoded key. You can generate it in python: import base64,crypt;crypt.crypt(base64.b64encode('your_username:your_password'), salt)")

    args = parser.parse_args()

    if os.path.isdir(args.root):
        run(args.root, args.port, build_routing(args.route), args.key, args.salt)
    else:
        print("not a valid directory %s" % args.root)


if __name__ == '__main__':
    main()
