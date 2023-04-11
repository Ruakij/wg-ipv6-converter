# ---- Build ----
FROM golang:1.19-alpine AS build
WORKDIR /build
# Copy sources
ADD . .
# Get dependencies
RUN go get ./cmd/app
# Compile
RUN CGO_ENABLED=0 go build -a -o app ./cmd/app

# ---- Output ----
FROM scratch AS export-stage
COPY --from=build /build/app .
