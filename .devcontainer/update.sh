#!/bin/bash
# create virtual environment and install dependencies
rm -rf .venv
poetry install --sync --with dev
