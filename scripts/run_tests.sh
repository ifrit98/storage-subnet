#! /bin/bash
set -euxo pipefail

file_dirs="storage neurons"
black $file_dirs
isort $file_dirs
flake8 $file_dirs
bandit -r $file_dirs
pytest tests