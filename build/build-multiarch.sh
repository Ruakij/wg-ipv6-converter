PLATFORM="linux/amd64,linux/arm64/v8,linux/arm/v7"
EXTRA_ARGS="$@"

docker buildx build \
    --platform $PLATFORM \
    -f $(dirname $0)/Dockerfile \
    --output out \
    $EXTRA_ARGS \
    .
