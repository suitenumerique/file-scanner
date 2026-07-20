"""Pluggable scanner backends.

Each module implements ``scanner.Scanner`` for one engine and is registered by
public name in ``scanner._BUILDERS``: ``clamav.py`` (ClamAV over the clamd wire
protocol), ``exav.py`` (the drop-in exav, subclassing the ClamAV backend), and
``jcop.py`` (the cyber.gouv.fr HTTP service).
"""
