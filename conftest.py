"""Ensures repo root is importable for every test module."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))