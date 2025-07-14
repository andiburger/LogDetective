#!/bin/bash

# Build script for LogDetective Docker image with cache option and pre-build test


IMAGE_NAME="log_detective"

# Automatically detect platform
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)
    PLATFORM="linux/amd64"
    ;;
  aarch64 | arm64)
    PLATFORM="linux/arm64"
    ;;
  armv7l)
    PLATFORM="linux/arm/v7"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

show_help() {
  echo "Usage: $0 [version_tag] [--no-cache]"
  echo "  version_tag  Optional version tag for Docker image (default: latest or git tag or timestamp)"
  echo "  --no-cache   Build Docker image without using cache"
  echo "  -h, --help   Show this help message"
  exit 0
}

# Parse arguments
NO_CACHE=0
TAG=""
for arg in "$@"; do
  case $arg in
    --no-cache)
      NO_CACHE=1
      shift
      ;;
    -h|--help)
      show_help
      ;;
    *)
      if [ -z "$TAG" ]; then
        TAG="$arg"
      else
        echo "Unknown argument: $arg"
        show_help
      fi
      ;;
  esac
done

# Determine version tag if not given
if [ -z "$TAG" ]; then
  if git describe --tags --abbrev=0 >/dev/null 2>&1; then
    TAG=$(git describe --tags --abbrev=0)
  else
    TAG=$(date +"%Y%m%d%H%M")
  fi
fi

echo "Detected architecture: $ARCH → using platform: ${PLATFORM}"
echo "Running tests before build..."

pytest_output=$(pytest 2>&1)
pytest_exit_code=$?

echo "$pytest_output"

if [ $pytest_exit_code -ne 0 ]; then
  echo "❌ Tests failed, aborting build."
  exit 1
fi

echo "✅ Tests passed."

echo "Building Docker image: ${IMAGE_NAME}:${TAG} for platform ${PLATFORM}"

BUILD_ARGS="--platform ${PLATFORM} -t ${IMAGE_NAME}:${TAG} -t ${IMAGE_NAME}:latest"
if [ $NO_CACHE -eq 1 ]; then
  BUILD_ARGS="$BUILD_ARGS --no-cache"
fi

docker build $BUILD_ARGS .

if [ $? -eq 0 ]; then
  echo "✅ Build completed successfully: ${IMAGE_NAME}:${TAG} and ${IMAGE_NAME}:latest"
else
  echo "❌ Build failed."
  exit 1
fi