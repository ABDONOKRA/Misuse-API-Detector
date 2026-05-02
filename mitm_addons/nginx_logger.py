import mitmproxy.http
from datetime import datetime

class NginxLogger:
    def __init__(self):
        self.log_file = "/var/log/nginx/access.log"

    def response(self, flow: mitmproxy.http.HTTPFlow):
        now = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = flow.client_conn.peername[0]
        method = flow.request.method
        path = flow.request.path
        version = flow.request.http_version
        status = flow.response.status_code
        size = len(flow.response.content)
        ua = flow.request.headers.get("user-agent", "-")

        log_line = f'{ip} - - [{now}] "{method} {path} {version}" {status} {size} "-" "{ua}"\n'

        with open(self.log_file, "a") as f:
            f.write(log_line)

addons = [NginxLogger()]
