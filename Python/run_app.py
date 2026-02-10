import os
import sys

import streamlit.web.cli as stcli


def resolve_path(path):
    if getattr(sys, "frozen", False):
        base_dir = sys._MEIPASS
        return os.path.abspath(os.path.join(base_dir, path))
    return os.path.abspath(os.path.join(os.path.dirname(__file__), path))


if __name__ == "__main__":
    sys.argv = [
        "streamlit",
        "run",
        resolve_path("pcap_sentry_pro.py"),
        "--global.developmentMode=false",
        "--server.maxUploadSize=1024",
    ]
    sys.exit(stcli.main())
