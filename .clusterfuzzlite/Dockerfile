FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/pysfmea
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/pysfmea
RUN pip3 install --no-cache-dir .
