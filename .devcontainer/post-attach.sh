#!/bin/bash

rm -rf ./.venv
poetry install --sync --with dev,test
