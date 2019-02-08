FROM yastdevel/cpp
RUN zypper --gpg-auto-import-keys --non-interactive in --no-recommends \
  python3 python3-setuptools
COPY . /usr/src/app
