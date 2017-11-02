# HTTP Control

HTTP interface for running arbitrary commands at the server


# Usage

```sh
usage: http_cntrl.py [-h] [--root ROOT] [--port PORT] [--route ROUTE] --key
                     KEY

A simple backdoor HTTP server

optional arguments:
  -h, --help            show this help message and exit
  --root ROOT, -r ROOT  Root directory to serve scripts from
  --port PORT, -p PORT  port to run the server on
  --route ROUTE         route mapping in form of path:script_to_run, e.g.
                        restart:restart.sh
  --key KEY, -k KEY     sha1 encoded key. You can generate it in python:
                        import base64,hashlib;print(hashlib.sha1(base64.b64enc
                        ode('your_username:your_password')).hexdigest())
```


# Example

Run an HTTP server on port 8080 with the credentials read from standard input.

`./scripts/bootstrap`

