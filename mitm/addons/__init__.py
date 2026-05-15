"""Custom mitmproxy addons loaded into the vendored server.

Both files are loaded with `mitmdump -s` style, so they are not imported by
our Python entrypoint. Keep imports minimal so they remain fast.
"""
