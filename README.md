# HTTP Control

HTTP interface for running arbitrary commands at the server


# Usage

```sh
usage: http_cntrl.py [-h] [--root ROOT] [--port PORT] [--route ROUTE]
                     [--salt SALT] --key KEY

A simple backdoor HTTP server

optional arguments:
  -h, --help            show this help message and exit
  --root ROOT, -r ROOT  Root directory to serve scripts from
  --port PORT, -p PORT  port to run the server on
  --route ROUTE         route mapping in form of path:script_to_run, e.g.
                        restart:restart.sh
  --salt SALT, -s SALT  Crypt's salt parameter for crypt function. See --key
                        parameter
  --key KEY, -k KEY     base64 encoded key. You can generate it in python:
                        import base64,crypt;crypt.crypt(base64.b64encode('your
                        _username:your_password'), salt)
```


# Example

Run an HTTP server on port 8080 with the credentials read from standard input.

`./scripts/bootstrap`

