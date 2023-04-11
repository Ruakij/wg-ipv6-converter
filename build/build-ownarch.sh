EXTRA_ARGS="$@"

docker build \
    -f $(dirname $0)/Dockerfile \
    --output out \
    $EXTRA_ARGS \
    .
