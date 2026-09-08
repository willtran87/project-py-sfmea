FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/pysfmea
WORKDIR $SRC/pysfmea
RUN pip3 install --no-cache-dir .
